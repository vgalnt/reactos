
/* INCLUDES ******************************************************************/

#include <hal.h>
#define NDEBUG
#include <debug.h>

#if defined(ALLOC_PRAGMA) && !defined(_MINIHAL_)
  #pragma alloc_text(INIT, HalpInitDma)
#endif

/* GLOBALS *******************************************************************/

HALP_DMA_MASTER_ADAPTER MasterAdapter24;
HALP_DMA_MASTER_ADAPTER MasterAdapter32;
LIST_ENTRY HalpDmaAdapterList;
KSPIN_LOCK HalpDmaAdapterListLock;

static BOOLEAN HalpEisaDma = FALSE;
static KEVENT HalpDmaLock; // NT use HalpNewAdapter?
static PADAPTER_OBJECT HalpEisaAdapter[8];

static DMA_OPERATIONS HalpDmaOperations =
{
    sizeof(DMA_OPERATIONS),
    HalPutDmaAdapter,
    HalAllocateCommonBuffer,
    HalFreeCommonBuffer,
    IoAllocateAdapterChannel,
    IoFlushAdapterBuffers,
    IoFreeAdapterChannel,
    IoFreeMapRegisters,
    IoMapTransfer,
    HalpDmaGetDmaAlignment,
    HalReadDmaCounter,
    /* FIXME: Implement the S/G funtions. */
    HalGetScatterGatherList,
    HalPutScatterGatherList,
    HalCalculateScatterGatherListSize,
    HalBuildScatterGatherList,
    HalBuildMdlFromScatterGatherList
};

static const ULONG_PTR HalpEisaPortPage[8] = {
   FIELD_OFFSET(DMA_PAGE, Channel0),
   FIELD_OFFSET(DMA_PAGE, Channel1),
   FIELD_OFFSET(DMA_PAGE, Channel2),
   FIELD_OFFSET(DMA_PAGE, Channel3),
   0,
   FIELD_OFFSET(DMA_PAGE, Channel5),
   FIELD_OFFSET(DMA_PAGE, Channel6),
   FIELD_OFFSET(DMA_PAGE, Channel7)
};

extern ULONG HalpBusType;
extern BOOLEAN HalpPhysicalMemoryMayAppearAbove4GB;
extern BOOLEAN LessThan16Mb;

/* FUNCTIONS *****************************************************************/

/* HalpGetAdapterMaximumPhysicalAddress
      Get the maximum physical address acceptable by the device represented by the passed DMA adapter.
*/
PHYSICAL_ADDRESS
NTAPI
HalpGetAdapterMaximumPhysicalAddress(
    _In_ PADAPTER_OBJECT AdapterObject)
{
    PHYSICAL_ADDRESS HighestAddress;

    if (!AdapterObject->MasterDevice)
    {
        HighestAddress.QuadPart = 0xFFFFFF;
    }
    else if (AdapterObject->Dma64BitAddresses)
    {
        HighestAddress.QuadPart = 0xFFFFFFFFFFFFFFFFULL;
    }
    else if (AdapterObject->Dma32BitAddresses)
    {
        HighestAddress.QuadPart = 0xFFFFFFFF;
    }

    return HighestAddress;
}

/* HalpGrowMapBuffers
      Allocate initial, or additional, map buffers for DMA master adapter.

   MasterAdapter
     DMA master adapter to allocate buffers for.
   SizeOfMapBuffers
     Size of the map buffers to allocate (not including the size already allocated).
*/
BOOLEAN
NTAPI
HalpGrowMapBuffers(
    _In_ PADAPTER_OBJECT AdapterObject,
    _In_ ULONG SizeOfMapBuffers)
{
    PROS_MAP_REGISTER_ENTRY CurrentEntry;
    PROS_MAP_REGISTER_ENTRY PreviousEntry;
    PHYSICAL_ADDRESS PhysicalAddress;
    PHYSICAL_ADDRESS HighestAcceptableAddress;
    PHYSICAL_ADDRESS LowestAcceptableAddress;
    PHYSICAL_ADDRESS BoundryAddressMultiple;
    PVOID VirtualAddress;
    ULONG MapRegisterCount;
    KIRQL OldIrql;

    /* Check if enough map register slots are available. */
    MapRegisterCount = BYTES_TO_PAGES(SizeOfMapBuffers);
    if ((MapRegisterCount + AdapterObject->NumberOfMapRegisters) > MAX_MAP_REGISTERS)
    {
        DPRINT1("HalpGrowMapBuffers: No more map register slots available!\n");
        DPRINT1("HalpGrowMapBuffers: Current %X, Requested %X, Limit %X\n",
               AdapterObject->NumberOfMapRegisters, MapRegisterCount, MAX_MAP_REGISTERS);

        return FALSE;
    }

    /* Allocate memory for the new map registers.
       For 32-bit adapters we use two passes in order not to waste scare resource (low memory).
    */
    HighestAcceptableAddress = HalpGetAdapterMaximumPhysicalAddress(AdapterObject);

    LowestAcceptableAddress.HighPart = 0;
    LowestAcceptableAddress.LowPart = ((HighestAcceptableAddress.LowPart == 0xFFFFFFFF) ? 0x1000000 : 0);

    BoundryAddressMultiple.QuadPart = 0;

    VirtualAddress = 
    MmAllocateContiguousMemorySpecifyCache((MapRegisterCount << PAGE_SHIFT),
                                           LowestAcceptableAddress,
                                           HighestAcceptableAddress,
                                           BoundryAddressMultiple,
                                           MmNonCached);

    if (!VirtualAddress && LowestAcceptableAddress.LowPart)
    {
        LowestAcceptableAddress.LowPart = 0;

        VirtualAddress =
        MmAllocateContiguousMemorySpecifyCache((MapRegisterCount << PAGE_SHIFT),
                                               LowestAcceptableAddress,
                                               HighestAcceptableAddress,
                                               BoundryAddressMultiple,
                                               MmNonCached);
    }

    if (!VirtualAddress)
    {
        DPRINT1("HalpGrowMapBuffers: VirtualAddress is NULL!\n");
        return FALSE;
    }

    PhysicalAddress = MmGetPhysicalAddress(VirtualAddress);

    /* All the following must be done with the master adapter lock held to prevent corruption. */
    KeAcquireSpinLock(&AdapterObject->SpinLock, &OldIrql);

    /* Setup map register entries for the buffer allocated.
       Each entry has a virtual and physical address and corresponds to PAGE_SIZE large buffer.
    */
    CurrentEntry = (AdapterObject->MapRegisterBase + AdapterObject->NumberOfMapRegisters);

    for (; MapRegisterCount; MapRegisterCount--)
    {
        /* Leave one entry free for every non-contiguous memory region in the map register bitmap.
           This ensures that we can search using RtlFindClearBits for contiguous map register regions.

           Also for non-EISA DMA leave one free entry for every 64Kb break,
           because the DMA controller can handle only coniguous 64Kb regions.
        */
        if (CurrentEntry != AdapterObject->MapRegisterBase)
        {
            PreviousEntry = (CurrentEntry - 1);

            if ((PreviousEntry->PhysicalAddress.LowPart + PAGE_SIZE) == PhysicalAddress.LowPart)
            {
                if (!HalpEisaDma)
                {
                    if ((PreviousEntry->PhysicalAddress.LowPart ^ PhysicalAddress.LowPart) & 0xFFFF0000)
                    {
                        CurrentEntry++;
                        AdapterObject->NumberOfMapRegisters++;
                    }
                }
            }
            else
            {
                CurrentEntry++;
                AdapterObject->NumberOfMapRegisters++;
            }
        }

        RtlClearBit(AdapterObject->MapRegisters, (ULONG)(CurrentEntry - AdapterObject->MapRegisterBase));

        CurrentEntry->VirtualAddress = VirtualAddress;
        CurrentEntry->PhysicalAddress = PhysicalAddress;

        PhysicalAddress.LowPart += PAGE_SIZE;
        VirtualAddress = (PVOID)((ULONG_PTR)VirtualAddress + PAGE_SIZE);

        CurrentEntry++;
        AdapterObject->NumberOfMapRegisters++;
    }

    KeReleaseSpinLock(&AdapterObject->SpinLock, OldIrql);
    return TRUE;
}

/* HaliGetDmaAdapter
     Internal routine to allocate PnP DMA adapter object.
     It's exported through HalDispatchTable and used by IoGetDmaAdapter.
 
   see HalGetAdapter
*/
PDMA_ADAPTER
NTAPI
HaliGetDmaAdapter(
    _In_ PVOID Context,
    _In_ PDEVICE_DESCRIPTION DeviceDescriptor,
    _Out_ PULONG NumberOfMapRegisters)
{
    return &HalGetAdapter(DeviceDescriptor, NumberOfMapRegisters)->DmaHeader;
}

NTSTATUS
NTAPI
HalpAllocateMapRegisters(
    _In_ PADAPTER_OBJECT AdapterObject,
    _In_ ULONG Unknown,
    _In_ ULONG Unknown2,
    _In_ PMAP_REGISTER_ENTRY Registers)
{
    UNIMPLEMENTED;
    ASSERT(FALSE); // HalpDbgBreakPointEx();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
HaliLocateHiberRanges(
    _In_ PVOID MemoryMap)
{
    UNIMPLEMENTED;
    ASSERT(FALSE); // HalpDbgBreakPointEx();
}

INIT_FUNCTION
VOID
NTAPI
HalpInitDma(VOID)
{
    DPRINT("HalpInitDma()\n");

    if (HalpBusType == MACHINE_TYPE_EISA)
    {
        /* Check if Extended DMA is available. We're just going to do a random read and write. */
        WRITE_PORT_UCHAR(UlongToPtr(FIELD_OFFSET(EISA_CONTROL, DmaController2Pages.Channel2)), 0x2A);

        if (READ_PORT_UCHAR(UlongToPtr(FIELD_OFFSET(EISA_CONTROL, DmaController2Pages.Channel2))) == 0x2A)
        {
            DPRINT1("Machine supports EISA DMA. Bus type: %lu\n", HalpBusType);
            HalpEisaDma = TRUE;
        }
    }

    /* Intialize all the global variables and allocate master adapter with first map buffers. */
    KeInitializeEvent(&HalpDmaLock, NotificationEvent, TRUE);
}

PADAPTER_OBJECT
NTAPI
HalpAllocateAdapterEx(
    _In_ ULONG MapRegisters,
    _In_ PVOID AdapterBaseVa,
    _In_ BOOLEAN IsDma32Bit)
{
    PHALP_DMA_MASTER_ADAPTER pMasterAdapter;
    PROS_MAP_REGISTER_ENTRY MapRegisterBase;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PADAPTER_OBJECT MasterAdapter;
    PADAPTER_OBJECT AdapterObject;
    HANDLE Handle;
    PVOID Object;
    ULONG MapRegisterBaseSize;
    ULONG MapBufferMaxPages;
    ULONG SizeOfBitMap;
    ULONG AdapterSize;
    BOOLEAN IsMasterAdapter;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("HalpAllocateAdapterEx: %X, %X, %X\n", MapRegisters, AdapterBaseVa, IsDma32Bit);

    if (HalpPhysicalMemoryMayAppearAbove4GB && IsDma32Bit)
        pMasterAdapter = &MasterAdapter32;
    else
        pMasterAdapter = &MasterAdapter24;

    if (AdapterBaseVa == LongToPtr(-1))
    {
        IsMasterAdapter = TRUE;
    }
    else
    {
        IsMasterAdapter = FALSE;

        if (MapRegisters && pMasterAdapter->MasterAdapter == NULL)
        {
            MasterAdapter = HalpAllocateAdapterEx(MapRegisters, LongToPtr(-1), IsDma32Bit);
            if (!MasterAdapter)
            {
                DPRINT1("Alloc DMA AdapterObject failed!\n");
                return NULL;
            }

            MasterAdapter->Dma32BitAddresses = IsDma32Bit;
            MasterAdapter->MasterDevice = IsDma32Bit;

            pMasterAdapter->MasterAdapter = MasterAdapter;
        }
    }

    InitializeObjectAttributes(&ObjectAttributes,
                               NULL,
                               (OBJ_KERNEL_HANDLE | OBJ_PERMANENT),
                               NULL,
                               NULL);
    if (IsMasterAdapter)
    {
        MapBufferMaxPages = pMasterAdapter->MapBufferMaxPages;
        SizeOfBitMap = MapBufferMaxPages;
        AdapterSize = sizeof(ADAPTER_OBJECT) + ((((MapBufferMaxPages + 7) >> 3) + 11) & ~3);
    }
    else
    {
        AdapterSize = sizeof(ADAPTER_OBJECT);
    }

    Status = ObCreateObject(KernelMode,
                            IoAdapterObjectType,
                            &ObjectAttributes,
                            KernelMode,
                            NULL,
                            AdapterSize,
                            0,
                            0,
                            &Object);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpAllocateAdapterEx: Status %X\n", Status);
        return NULL;
    }

    AdapterObject = Object;

    Status = ObReferenceObjectByPointer(AdapterObject,
                                        (FILE_READ_DATA | FILE_WRITE_DATA),
                                        IoAdapterObjectType,
                                        KernelMode);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpAllocateAdapterEx: Status %X\n", Status);
        return NULL;
    }

    RtlZeroMemory(AdapterObject, sizeof(ADAPTER_OBJECT));

    Status = ObInsertObject(AdapterObject,
                            NULL,
                            (FILE_READ_DATA | FILE_WRITE_DATA),
                            0,
                            NULL,
                            &Handle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpAllocateAdapterEx: Status - %X\n", Status);
        return NULL;
    }

    ZwClose(Handle);

    AdapterObject->DmaHeader.Version = 1;
    AdapterObject->DmaHeader.Size = AdapterSize;
    AdapterObject->DmaHeader.DmaOperations = &HalpDmaOperations;

    AdapterObject->MapRegistersPerChannel = 1;
    AdapterObject->AdapterBaseVa = AdapterBaseVa;
    AdapterObject->ChannelNumber = 0xFF;
    AdapterObject->Dma32BitAddresses = IsDma32Bit;

    if (MapRegisters)
    {
        AdapterObject->MasterAdapter = pMasterAdapter->MasterAdapter;
        DPRINT1("HalpAllocateAdapterEx: MasterAdapter %p\n", AdapterObject->MasterAdapter);
    }
    else
    {
        AdapterObject->MasterAdapter = NULL;
    }

    KeInitializeDeviceQueue(&AdapterObject->ChannelWaitQueue);

    if (!IsMasterAdapter)
    {
        DPRINT("HalpAllocateAdapterEx: return %p\n", AdapterObject);
        return AdapterObject;
    }

    KeInitializeSpinLock(&AdapterObject->SpinLock);
    InitializeListHead(&AdapterObject->AdapterQueue);

    AdapterObject->MapRegisters = (PVOID)(MasterAdapter + 1);

    RtlInitializeBitMap(AdapterObject->MapRegisters,
                        (PULONG)(AdapterObject->MapRegisters + 1),
                        SizeOfBitMap);

    RtlSetAllBits(AdapterObject->MapRegisters);

    AdapterObject->NumberOfMapRegisters = 0;
    AdapterObject->CommittedMapRegisters = 0;

    MapRegisterBaseSize = (SizeOfBitMap * sizeof(ROS_MAP_REGISTER_ENTRY));
    MapRegisterBase = ExAllocatePoolWithTag(NonPagedPool, MapRegisterBaseSize, ' laH');

    AdapterObject->MapRegisterBase = MapRegisterBase;
    if (!MapRegisterBase)
    {
        DPRINT1("HalpAllocateAdapterEx: failed for AdapterObject %p\n", AdapterObject);
        ObDereferenceObject(AdapterObject);
        return NULL;
    }

    RtlZeroMemory(MapRegisterBase, MapRegisterBaseSize);

    if (!HalpGrowMapBuffers(AdapterObject, 0x10000))
    {
        DPRINT1("HalpAllocateAdapterEx: failed for AdapterObject %p\n", AdapterObject);
        ObDereferenceObject(AdapterObject);
        return NULL;
    }

    DPRINT1("HalpAllocateAdapterEx: Allocated %p\n", AdapterObject);
    return AdapterObject;
}

VOID
NTAPI
HalPutDmaAdapter(
    _In_ PDMA_ADAPTER DmaAdapter)
{
    PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    KIRQL OldIrql;

    if (AdapterObject->ChannelNumber == 0xFF)
    {
        KeAcquireSpinLock(&HalpDmaAdapterListLock, &OldIrql);
        RemoveEntryList(&AdapterObject->AdapterList);
        KeReleaseSpinLock(&HalpDmaAdapterListLock, OldIrql);
    }

    ObDereferenceObject(AdapterObject);
}

PVOID
NTAPI
HalAllocateCommonBuffer(
    _In_ PDMA_ADAPTER DmaAdapter,
    _In_ ULONG Length,
    _In_ PPHYSICAL_ADDRESS LogicalAddress,
    _In_ BOOLEAN CacheEnabled)
{
    PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    PHYSICAL_ADDRESS LowestAcceptableAddress;
    PHYSICAL_ADDRESS HighestAcceptableAddress;
    PHYSICAL_ADDRESS BoundryAddressMultiple;
    PVOID VirtualAddress;

    LowestAcceptableAddress.QuadPart = 0;
    BoundryAddressMultiple.QuadPart = 0;

    HighestAcceptableAddress = HalpGetAdapterMaximumPhysicalAddress(AdapterObject);

    /* For bus-master DMA devices the buffer mustn't cross 4Gb boundary.
       For slave DMA devices the 64Kb boundary mustn't be crossed since the controller wouldn't be able to handle it.
    */
    if (AdapterObject->MasterDevice)
        BoundryAddressMultiple.HighPart = 1;
    else
        BoundryAddressMultiple.LowPart = 0x10000;

    VirtualAddress =
    MmAllocateContiguousMemorySpecifyCache(Length,
                                           LowestAcceptableAddress,
                                           HighestAcceptableAddress,
                                           BoundryAddressMultiple,
                                           (CacheEnabled ? MmCached : MmNonCached));
    if (!VirtualAddress)
        return NULL;

    *LogicalAddress = MmGetPhysicalAddress(VirtualAddress);

    return VirtualAddress;
}

BOOLEAN
NTAPI
HalFlushCommonBuffer(
    _In_ PDMA_ADAPTER DmaAdapter,
    _In_ ULONG Length,
    _In_ PHYSICAL_ADDRESS LogicalAddress,
    _In_ PVOID VirtualAddress)
{
    /* Function always returns true */
    return TRUE;
}

VOID
NTAPI
HalFreeCommonBuffer(
    _In_ PDMA_ADAPTER DmaAdapter,
    _In_ ULONG Length,
    _In_ PHYSICAL_ADDRESS LogicalAddress,
    _In_ PVOID VirtualAddress,
    _In_ BOOLEAN CacheEnabled)
{
    MmFreeContiguousMemorySpecifyCache(VirtualAddress, Length, (CacheEnabled ? MmCached : MmNonCached));
}

/* HalpCopyBufferMap
      Helper function for copying data from/to map register buffers.
 
   see IoFlushAdapterBuffers, IoMapTransfer
*/
VOID
NTAPI
HalpCopyBufferMap(
    _In_ PMDL Mdl,
    _In_ PROS_MAP_REGISTER_ENTRY MapRegisterBase,
    _In_ PVOID CurrentVa,
    _In_ ULONG Length,
    _In_ BOOLEAN WriteToDevice)
{
    ULONG CurrentLength;
    ULONG_PTR CurrentAddress;
    ULONG ByteOffset;
    PVOID VirtualAddress;

    VirtualAddress = MmGetSystemAddressForMdlSafe(Mdl, HighPagePriority);
    if (!VirtualAddress)
    {
        /* NOTE: On real NT a mechanism with reserved pages is implemented
           to handle this case in a slow, but graceful non-fatal way.
        */
        DPRINT1("HalpCopyBufferMap: KeBugCheckEx(HAL_MEMORY_ALLOCATION)\n");
        KeBugCheckEx(HAL_MEMORY_ALLOCATION, PAGE_SIZE, 0, (ULONG_PTR)__FILE__, 0);
    }

    CurrentAddress = (ULONG_PTR)VirtualAddress +
                     (ULONG_PTR)CurrentVa -
                     (ULONG_PTR)MmGetMdlVirtualAddress(Mdl);

    for (; Length > 0; Length -= CurrentLength)
    {
        ByteOffset = BYTE_OFFSET(CurrentAddress);
        CurrentLength = PAGE_SIZE - ByteOffset;

        if (CurrentLength > Length)
            CurrentLength = Length;

        if (WriteToDevice)
        {
            RtlCopyMemory((PVOID)((ULONG_PTR)MapRegisterBase->VirtualAddress + ByteOffset),
                          (PVOID)CurrentAddress,
                          CurrentLength);
        }
        else
        {
            RtlCopyMemory((PVOID)CurrentAddress,
                          (PVOID)((ULONG_PTR)MapRegisterBase->VirtualAddress + ByteOffset),
                          CurrentLength);
        }

        CurrentAddress += CurrentLength;
        MapRegisterBase++;
    }
}

/* IoFlushAdapterBuffers
      Flush any data remaining in the DMA controller's memory into the host memory.

   AdapterObject
      The adapter object to flush.

   Mdl
      Original MDL to flush data into.

   MapRegisterBase
      Map register base that was just used by IoMapTransfer, etc.

   CurrentVa
      Offset into Mdl to be flushed into, same as was passed to IoMapTransfer.

   Length
      Length of the buffer to be flushed into.

   WriteToDevice
     TRUE if it's a write, FALSE if it's a read.

   return: TRUE in all cases.

   This copies data from the map register-backed buffer to the user's target buffer.
   Data are not in the user buffer until this function is called.
   For slave DMA transfers the controller channel is masked effectively stopping the current transfer.
*/
BOOLEAN
NTAPI
IoFlushAdapterBuffers(
    _In_ PDMA_ADAPTER DmaAdapter,
    _In_ PMDL Mdl,
    _In_ PVOID MapRegisterBase,
    _In_ PVOID CurrentVa,
    _In_ ULONG Length,
    _In_ BOOLEAN WriteToDevice)
{
    PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    PROS_MAP_REGISTER_ENTRY RealMapRegisterBase;
    PHYSICAL_ADDRESS HighestAcceptableAddress;
    PHYSICAL_ADDRESS PhysicalAddress;
    PPFN_NUMBER MdlPagesPtr;
    BOOLEAN SlaveDma = FALSE;

    /* Sanity checks */
    ASSERT_IRQL_LESS_OR_EQUAL(DISPATCH_LEVEL);
    ASSERT(AdapterObject);

    if (!AdapterObject->MasterDevice)
    {
        /* Mask out (disable) the DMA channel. */
        if (AdapterObject->AdapterNumber == 1)
        {
            PDMA1_CONTROL DmaControl1 = AdapterObject->AdapterBaseVa;
            WRITE_PORT_UCHAR(&DmaControl1->SingleMask, (AdapterObject->ChannelNumber | DMA_SETMASK));
        }
        else
        {
            PDMA2_CONTROL DmaControl2 = AdapterObject->AdapterBaseVa;
            WRITE_PORT_UCHAR(&DmaControl2->SingleMask, (AdapterObject->ChannelNumber | DMA_SETMASK));
        }

        SlaveDma = TRUE;
    }

    /* This can happen if the device supports hardware scatter/gather. */
    if (!MapRegisterBase)
        return TRUE;

    RealMapRegisterBase = (PROS_MAP_REGISTER_ENTRY)((ULONG_PTR)MapRegisterBase & ~MAP_BASE_SW_SG);

    if (WriteToDevice)
        goto Exit;

    if ((ULONG_PTR)MapRegisterBase & MAP_BASE_SW_SG)
    {
        if (RealMapRegisterBase->Counter != MAXULONG)
        {
            if (SlaveDma && !AdapterObject->IgnoreCount)
                Length -= HalReadDmaCounter(DmaAdapter);
        }

        HalpCopyBufferMap(Mdl, RealMapRegisterBase, CurrentVa, Length, FALSE);
        goto Exit;
    }

    MdlPagesPtr = MmGetMdlPfnArray(Mdl);
    MdlPagesPtr += (((ULONG_PTR)CurrentVa - (ULONG_PTR)Mdl->StartVa) >> PAGE_SHIFT);

    PhysicalAddress.QuadPart = (*MdlPagesPtr << PAGE_SHIFT);
    PhysicalAddress.QuadPart += BYTE_OFFSET(CurrentVa);

    HighestAcceptableAddress = HalpGetAdapterMaximumPhysicalAddress(AdapterObject);

    if ((PhysicalAddress.QuadPart + Length) <= HighestAcceptableAddress.QuadPart)
    {
        DPRINT1("IoFlushAdapterBuffers: %I64X, %I64X\n",
                (PhysicalAddress.QuadPart + Length), HighestAcceptableAddress.QuadPart);

        goto Exit;
    }

    HalpCopyBufferMap(Mdl, RealMapRegisterBase, CurrentVa, Length, FALSE);

Exit:
    RealMapRegisterBase->Counter = 0;
    return TRUE;
}

/* IoFreeAdapterChannel
      Free DMA resources allocated by IoAllocateAdapterChannel.

   AdapterObject
      Adapter object with resources to free.

   This function releases map registers registers assigned to the DMA adapter.
   After releasing the adapter, it checks the adapter's queue
   and runs each queued device object in series until the queue is empty.
   This is the only way the device queue is emptied.
  
   see IoAllocateAdapterChannel
*/
VOID
NTAPI
IoFreeAdapterChannel(
    _In_ PDMA_ADAPTER DmaAdapter)
{
    PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    PADAPTER_OBJECT MasterAdapter;
    PKDEVICE_QUEUE_ENTRY DeviceQueueEntry;
    PWAIT_CONTEXT_BLOCK WaitContextBlock;
    ULONG Index = MAXULONG;
    ULONG Result;
    KIRQL OldIrql;

    MasterAdapter = AdapterObject->MasterAdapter;

    for (;;)
    {
        /* To keep map registers, call here with AdapterObject->NumberOfMapRegisters set to zero.
           This trick is used in HalAllocateAdapterChannel for example.
        */
        if (AdapterObject->NumberOfMapRegisters)
        {
            IoFreeMapRegisters(DmaAdapter,
                               AdapterObject->MapRegisterBase,
                               AdapterObject->NumberOfMapRegisters);
        }

        DeviceQueueEntry = KeRemoveDeviceQueue(&AdapterObject->ChannelWaitQueue);
        if (!DeviceQueueEntry)
            break;

        WaitContextBlock = CONTAINING_RECORD(DeviceQueueEntry, WAIT_CONTEXT_BLOCK, WaitQueueEntry);

        AdapterObject->CurrentWcb = WaitContextBlock;
        AdapterObject->NumberOfMapRegisters = WaitContextBlock->NumberOfMapRegisters;

        if ((WaitContextBlock->NumberOfMapRegisters) && (AdapterObject->MasterAdapter))
        {
            KeAcquireSpinLock(&MasterAdapter->SpinLock, &OldIrql);

            if (IsListEmpty(&MasterAdapter->AdapterQueue))
            {
                Index = RtlFindClearBitsAndSet(MasterAdapter->MapRegisters, WaitContextBlock->NumberOfMapRegisters, 0);
                if (Index != MAXULONG)
                {
                    AdapterObject->MapRegisterBase = MasterAdapter->MapRegisterBase + Index;
                    if (!AdapterObject->ScatterGather)
                    {
                        AdapterObject->MapRegisterBase =
                        (PROS_MAP_REGISTER_ENTRY)((ULONG_PTR)AdapterObject->MapRegisterBase | MAP_BASE_SW_SG);
                    }
                }
            }

            if (Index == MAXULONG)
            {
                InsertTailList(&MasterAdapter->AdapterQueue, &AdapterObject->AdapterQueue);
                KeReleaseSpinLock(&MasterAdapter->SpinLock, OldIrql);
                break;
            }

            KeReleaseSpinLock(&MasterAdapter->SpinLock, OldIrql);
        }
        else
        {
            AdapterObject->MapRegisterBase = NULL;
            AdapterObject->NumberOfMapRegisters = 0;
        }

        /* Call the adapter control routine. */
        Result = ((PDRIVER_CONTROL)WaitContextBlock->DeviceRoutine)(WaitContextBlock->DeviceObject,
                                                                    WaitContextBlock->CurrentIrp,
                                                                    AdapterObject->MapRegisterBase,
                                                                    WaitContextBlock->DeviceContext);
        switch (Result)
        {
            case KeepObject:
                /* We're done until the caller manually calls IoFreeAdapterChannel or IoFreeMapRegisters. */
                return;

            case DeallocateObjectKeepRegisters:
                /* Hide the map registers so they aren't deallocated next time around. */
                AdapterObject->NumberOfMapRegisters = 0;
                break;

            default:
                break;
        }
    }
}

/* IoFreeMapRegisters
      Free map registers reserved by the system for a DMA.
 
   AdapterObject
     DMA adapter to free map registers on.

   MapRegisterBase
     Handle to map registers to free.

   NumberOfRegisters
     Number of map registers to be freed.
*/
VOID
NTAPI
IoFreeMapRegisters(
    _In_ PDMA_ADAPTER DmaAdapter,
    _In_ PVOID MapRegisterBase,
    _In_ ULONG NumberOfMapRegisters)
{
    PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    PADAPTER_OBJECT MasterAdapter = AdapterObject->MasterAdapter;
    PLIST_ENTRY ListEntry;
    KIRQL OldIrql;
    ULONG Index;
    ULONG Result;

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    if (!MasterAdapter)
    {
        DPRINT("IoFreeMapRegisters: MasterAdapter is NULL\n");
        return;
    }

    if (!MapRegisterBase)
    {
        DPRINT1("IoFreeMapRegisters: MapRegisterBase is NULL\n");
        return;
    }

    KeAcquireSpinLock(&MasterAdapter->SpinLock, &OldIrql);

    if (NumberOfMapRegisters != 0)
    {
        PROS_MAP_REGISTER_ENTRY RealMapRegisterBase;

        RealMapRegisterBase = (PROS_MAP_REGISTER_ENTRY)((ULONG_PTR)MapRegisterBase & ~MAP_BASE_SW_SG);

        RtlClearBits(MasterAdapter->MapRegisters,
                     (ULONG)(RealMapRegisterBase - MasterAdapter->MapRegisterBase),
                     NumberOfMapRegisters);
    }

    /* Now that we freed few map registers it's time to look at the master
       adapter queue and see if there is someone waiting for map registers.
    */
    while (!IsListEmpty(&MasterAdapter->AdapterQueue))
    {
        ListEntry = RemoveHeadList(&MasterAdapter->AdapterQueue);
        AdapterObject = CONTAINING_RECORD(ListEntry, struct _ADAPTER_OBJECT, AdapterQueue);

        Index = RtlFindClearBitsAndSet(MasterAdapter->MapRegisters, AdapterObject->NumberOfMapRegisters, 0);
        if (Index == MAXULONG)
        {
            InsertHeadList(&MasterAdapter->AdapterQueue, ListEntry);
            break;
        }

        KeReleaseSpinLock(&MasterAdapter->SpinLock, OldIrql);

        AdapterObject->MapRegisterBase = MasterAdapter->MapRegisterBase + Index;

        if (!AdapterObject->ScatterGather)
        {
            AdapterObject->MapRegisterBase =
            (PROS_MAP_REGISTER_ENTRY)((ULONG_PTR)AdapterObject->MapRegisterBase | MAP_BASE_SW_SG);
        }

        Result = ((PDRIVER_CONTROL)AdapterObject->CurrentWcb->DeviceRoutine)(AdapterObject->CurrentWcb->DeviceObject,
                                                                             AdapterObject->CurrentWcb->CurrentIrp,
                                                                             AdapterObject->MapRegisterBase,
                                                                             AdapterObject->CurrentWcb->DeviceContext);
        switch (Result)
        {
            case DeallocateObjectKeepRegisters:
                AdapterObject->NumberOfMapRegisters = 0;
                /* fall through */

            case DeallocateObject:
                if (AdapterObject->NumberOfMapRegisters)
                {
                    KeAcquireSpinLock(&MasterAdapter->SpinLock, &OldIrql);

                    RtlClearBits(MasterAdapter->MapRegisters,
                                 (ULONG)(AdapterObject->MapRegisterBase - MasterAdapter->MapRegisterBase),
                                 AdapterObject->NumberOfMapRegisters);

                    KeReleaseSpinLock(&MasterAdapter->SpinLock, OldIrql);
                }

                IoFreeAdapterChannel(DmaAdapter);
                break;

            default:
                break;
        }

        KeAcquireSpinLock(&MasterAdapter->SpinLock, &OldIrql);
    }

    KeReleaseSpinLock(&MasterAdapter->SpinLock, OldIrql);
}

/* IoMapTransfer
      Map a DMA for transfer and do the DMA if it's a slave.

   AdapterObject
      Adapter object to do the DMA on. Bus-master may pass NULL.

   Mdl
      Locked-down user buffer to DMA in to or out of.

   MapRegisterBase
      Handle to map registers to use for this dma.

   CurrentVa
      Index into Mdl to transfer into/out of.

   Length
      Length of transfer. Number of bytes actually transferred on output.

   WriteToDevice
      TRUE if it's an output DMA, FALSE otherwise.

   return: A logical address that can be used to program a DMA controller,
           it's not meaningful for slave DMA device.

   This function does a copyover to contiguous memory <16MB represented by the map registers if needed.
   If the buffer described by MDL can be used as is no copyover is done.
   If it's a slave transfer, this function actually performs it.
*/
PHYSICAL_ADDRESS
NTAPI
IoMapTransfer(
    _In_ PDMA_ADAPTER DmaAdapter,
    _In_ PMDL Mdl,
    _In_ PVOID MapRegisterBase,
    _In_ PVOID CurrentVa,
    _Inout_ PULONG Length,
    _In_ BOOLEAN WriteToDevice)
{
    PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    PROS_MAP_REGISTER_ENTRY RealMapRegisterBase;
    PHYSICAL_ADDRESS HighestAcceptableAddress;
    PHYSICAL_ADDRESS PhysicalAddress;
    PDMA1_CONTROL DmaControl1;
    PDMA2_CONTROL DmaControl2;
    PPFN_NUMBER MdlPagesPtr;
    PFN_NUMBER MdlPage1;
    PFN_NUMBER MdlPage2;
    DMA_MODE AdapterMode;
    ULONG ByteOffset;
    ULONG TransferOffset;
    ULONG TransferLength;
    ULONG Counter;
    BOOLEAN UseMapRegisters;
    KIRQL OldIrql;
    PUCHAR Port;

    /* Precalculate some values that are used in all cases.

       ByteOffset is offset inside the page at which the transfer starts.
       MdlPagesPtr is pointer inside the MDL page chain at the page where the transfer start.
       PhysicalAddress is physical address corresponding to the transfer start page and offset.
       TransferLength is the initial length of the transfer, which is reminder of the first page.
          The actual value is calculated below.

       Note that all the variables can change during the processing which takes place below.
       These are just initial values.
    */
    ByteOffset = BYTE_OFFSET(CurrentVa);

    MdlPagesPtr = MmGetMdlPfnArray(Mdl);
    MdlPagesPtr += (((ULONG_PTR)CurrentVa - (ULONG_PTR)Mdl->StartVa) >> PAGE_SHIFT);

    PhysicalAddress.QuadPart = (*MdlPagesPtr << PAGE_SHIFT);
    PhysicalAddress.QuadPart += ByteOffset;

    TransferLength = PAGE_SIZE - ByteOffset;

    /* Special case for bus master adapters with S/G support.
       We can directly use the buffer specified by the MDL, so not much work has to be done.
     *
       Just return the passed VA's corresponding physical address
       and update length to the number of physically contiguous bytes found.
       Also pages crossing the 4Gb boundary aren't considered physically contiguous.
    */
    if (MapRegisterBase == NULL)
    {
        for (; TransferLength < *Length; TransferLength += PAGE_SIZE)
        {
            MdlPage1 = *MdlPagesPtr;
            MdlPage2 = *(MdlPagesPtr + 1);

            if (MdlPage1 + 1 != MdlPage2)
                break;

            if ((MdlPage1 ^ MdlPage2) & ~0xFFFFF)
                break;

            MdlPagesPtr++;
        }

        if (TransferLength < *Length)
            *Length = TransferLength;

        return PhysicalAddress;
    }

    /* The code below applies to slave DMA adapters and bus master adapters without hardward S/G support. */
    RealMapRegisterBase = (PROS_MAP_REGISTER_ENTRY)((ULONG_PTR)MapRegisterBase & ~MAP_BASE_SW_SG);

    /* Try to calculate the size of the transfer.
       We can only transfer pages that are physically contiguous and that don't cross
       the 64Kb boundary (this limitation applies only for ISA controllers).
    */
    for (; TransferLength < *Length; TransferLength += PAGE_SIZE)
    {
        MdlPage1 = *MdlPagesPtr;
        MdlPage2 = *(MdlPagesPtr + 1);

        if (MdlPage1 + 1 != MdlPage2)
            break;

        if (!HalpEisaDma && ((MdlPage1 ^ MdlPage2) & ~0xF))
            break;

        MdlPagesPtr++;
    }

    if (TransferLength > *Length)
        TransferLength = *Length;

    /* If we're about to simulate software S/G and not all the pages are
       physically contiguous then we must use the map registers to store
       the data and allow the whole transfer to proceed at once.
    */
    if (((ULONG_PTR)MapRegisterBase & MAP_BASE_SW_SG) && (TransferLength < *Length))
    {
        UseMapRegisters = TRUE;

        PhysicalAddress = RealMapRegisterBase->PhysicalAddress;
        PhysicalAddress.QuadPart += ByteOffset;

        TransferLength = *Length;
        RealMapRegisterBase->Counter = MAXULONG;

        Counter = 0;
    }
    else
    {
        /* This is ordinary DMA transfer, so just update the progress counters.
           These are used by IoFlushAdapterBuffers to track the transfer progress.
        */
        UseMapRegisters = FALSE;
        Counter = RealMapRegisterBase->Counter;
        RealMapRegisterBase->Counter += (BYTES_TO_PAGES(ByteOffset + TransferLength));

        /* Check if the buffer doesn't exceed the highest physical address limit of the device.
           In that case we must use the map registers to store the data.
        */
        HighestAcceptableAddress = HalpGetAdapterMaximumPhysicalAddress(AdapterObject);

        if ((PhysicalAddress.QuadPart + TransferLength) > HighestAcceptableAddress.QuadPart)
        {
            UseMapRegisters = TRUE;

            PhysicalAddress = RealMapRegisterBase[Counter].PhysicalAddress;
            PhysicalAddress.QuadPart += ByteOffset;

            if ((ULONG_PTR)MapRegisterBase & MAP_BASE_SW_SG)
            {
                RealMapRegisterBase->Counter = MAXULONG;
                Counter = 0;
            }
        }
    }

    /* If we decided to use the map registers (see above) and we're about
       to transfer data to the device then copy the buffers into the map register memory.
    */
    if (UseMapRegisters && WriteToDevice)
    {
        HalpCopyBufferMap(Mdl,
                          (RealMapRegisterBase + Counter),
                          CurrentVa,
                          TransferLength,
                          WriteToDevice);
    }

    /* Return the length of transfer that actually takes place. */
    *Length = TransferLength;

    /* If we're doing slave (system) DMA then program the (E)ISA controller to actually start the transfer. */
    if (!AdapterObject || AdapterObject->MasterDevice)
        goto Exit;

    AdapterMode = AdapterObject->AdapterMode;

    if (WriteToDevice)
    {
        AdapterMode.TransferType = WRITE_TRANSFER;
    }
    else
    {
        AdapterMode.TransferType = READ_TRANSFER;

        if (AdapterObject->IgnoreCount)
            RtlZeroMemory((PUCHAR)RealMapRegisterBase[Counter].VirtualAddress + ByteOffset, TransferLength);
    }

    TransferOffset = (PhysicalAddress.LowPart & 0xFFFF);

    if (AdapterObject->Width16Bits)
    {
        TransferLength >>= 1;
        TransferOffset >>= 1;
    }

    KeAcquireSpinLock(&AdapterObject->MasterAdapter->SpinLock, &OldIrql);

    if (AdapterObject->AdapterNumber == 1)
    {
        DmaControl1 = AdapterObject->AdapterBaseVa;

        /* Reset Register */
        WRITE_PORT_UCHAR(&DmaControl1->ClearBytePointer, 0);

        /* Set the Mode */
        WRITE_PORT_UCHAR(&DmaControl1->Mode, AdapterMode.Byte);

        /* Set the Offset Register */
        Port = &DmaControl1->DmaAddressCount[AdapterObject->ChannelNumber].DmaBaseAddress;
        WRITE_PORT_UCHAR(Port, (UCHAR)(TransferOffset));
        WRITE_PORT_UCHAR(Port, (UCHAR)(TransferOffset >> 8));

        /* Set the Page Register */
        Port = AdapterObject->PagePort + FIELD_OFFSET(EISA_CONTROL, DmaController1Pages);
        WRITE_PORT_UCHAR(Port, (UCHAR)(PhysicalAddress.LowPart >> 16));

        if (HalpEisaDma)
            WRITE_PORT_UCHAR((AdapterObject->PagePort + FIELD_OFFSET(EISA_CONTROL, DmaController2Pages)), 0);

        /* Set the Length */
        Port = &DmaControl1->DmaAddressCount[AdapterObject->ChannelNumber].DmaBaseCount;
        WRITE_PORT_UCHAR(Port, (UCHAR)(TransferLength - 1));
        WRITE_PORT_UCHAR(Port, (UCHAR)((TransferLength - 1) >> 8));

        /* Unmask the Channel */
        WRITE_PORT_UCHAR(&DmaControl1->SingleMask, AdapterObject->ChannelNumber | DMA_CLEARMASK);

        KeReleaseSpinLock(&AdapterObject->MasterAdapter->SpinLock, OldIrql);

        goto Exit;
    }

    DmaControl2 = AdapterObject->AdapterBaseVa;

    /* Reset Register */
    WRITE_PORT_UCHAR(&DmaControl2->ClearBytePointer, 0);

    /* Set the Mode */
    WRITE_PORT_UCHAR(&DmaControl2->Mode, AdapterMode.Byte);

    /* Set the Offset Register */
    Port = &DmaControl2->DmaAddressCount[AdapterObject->ChannelNumber].DmaBaseAddress;
    WRITE_PORT_UCHAR(Port, (UCHAR)(TransferOffset));
    WRITE_PORT_UCHAR(Port, (UCHAR)(TransferOffset >> 8));

    /* Set the Page Register */
    Port = (AdapterObject->PagePort + FIELD_OFFSET(EISA_CONTROL, DmaController1Pages));
    WRITE_PORT_UCHAR(Port, (UCHAR)(PhysicalAddress.u.LowPart >> 16));

    if (HalpEisaDma)
        WRITE_PORT_UCHAR(AdapterObject->PagePort + FIELD_OFFSET(EISA_CONTROL, DmaController2Pages), 0);

    /* Set the Length */
    Port = &DmaControl2->DmaAddressCount[AdapterObject->ChannelNumber].DmaBaseCount;
    WRITE_PORT_UCHAR(Port, (UCHAR)(TransferLength - 1));
    WRITE_PORT_UCHAR(Port, (UCHAR)((TransferLength - 1) >> 8));

    /* Unmask the Channel */
    WRITE_PORT_UCHAR(&DmaControl2->SingleMask, AdapterObject->ChannelNumber | DMA_CLEARMASK);

    KeReleaseSpinLock(&AdapterObject->MasterAdapter->SpinLock, OldIrql);

Exit:

    /* Return physical address of the buffer with data that is used for the transfer.
       It can either point inside the Mdl that was passed by the caller
       or into the map registers if the Mdl buffer can't be used  directly.
    */
    return PhysicalAddress;
}

ULONG
NTAPI
HalpDmaGetDmaAlignment(
    _In_ PDMA_ADAPTER DmaAdapter)
{
    //PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    UNIMPLEMENTED;
    ASSERT(FALSE); // HalpDbgBreakPointEx();
    return 0;
}

ULONG
NTAPI
HalReadDmaCounter(
    _In_ PDMA_ADAPTER DmaAdapter)
{
    //PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    UNIMPLEMENTED;
    ASSERT(FALSE); // HalpDbgBreakPointEx();
    return 0;
}

IO_ALLOCATION_ACTION
NTAPI
HalpScatterGatherAdapterControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID MapRegisterBase,
    _In_ PVOID Context)
{
    PSCATTER_GATHER_CONTEXT AdapterControlContext = Context;
    PADAPTER_OBJECT AdapterObject = AdapterControlContext->AdapterObject;
    PSCATTER_GATHER_LIST ScatterGatherList;
    SCATTER_GATHER_ELEMENT TempElements[MAX_SG_ELEMENTS];
    ULONG ElementCount = 0, RemainingLength = AdapterControlContext->Length;
    PUCHAR CurrentVa = AdapterControlContext->CurrentVa;

    /* Store the map register base for later in HalPutScatterGatherList */
    AdapterControlContext->MapRegisterBase = MapRegisterBase;

    while (RemainingLength > 0 && ElementCount < MAX_SG_ELEMENTS)
    {
        TempElements[ElementCount].Length = RemainingLength;
        TempElements[ElementCount].Reserved = 0;
        TempElements[ElementCount].Address = IoMapTransfer((PDMA_ADAPTER)AdapterObject,
                                                           AdapterControlContext->Mdl,
                                                           MapRegisterBase,
                                                           (CurrentVa + (AdapterControlContext->Length - RemainingLength)),
                                                           &TempElements[ElementCount].Length,
                                                           AdapterControlContext->WriteToDevice);
        if (TempElements[ElementCount].Length == 0)
            break;

        DPRINT("Allocated one S/G element: 0x%I64u with length: 0x%x\n",
                TempElements[ElementCount].Address.QuadPart, TempElements[ElementCount].Length);

        ASSERT(TempElements[ElementCount].Length <= RemainingLength);

        RemainingLength -= TempElements[ElementCount].Length;
        ElementCount++;
    }

    if (RemainingLength > 0)
    {
        DPRINT1("Scatter/gather list construction failed!\n");
        return DeallocateObject;
    }

    ScatterGatherList = ExAllocatePoolWithTag(NonPagedPool,
                                              (sizeof(SCATTER_GATHER_LIST) + sizeof(SCATTER_GATHER_ELEMENT) * ElementCount),
                                              TAG_DMA);
    ASSERT(ScatterGatherList);

    ScatterGatherList->NumberOfElements = ElementCount;
    ScatterGatherList->Reserved = (ULONG_PTR)AdapterControlContext;

    RtlCopyMemory(ScatterGatherList->Elements,
                  TempElements,
                  (sizeof(SCATTER_GATHER_ELEMENT) * ElementCount));

    DPRINT("Initiating S/G DMA with %d element(s)\n", ElementCount);

    AdapterControlContext->AdapterListControlRoutine(DeviceObject,
                                                     Irp,
                                                     ScatterGatherList,
                                                     AdapterControlContext->AdapterListControlContext);

    return DeallocateObjectKeepRegisters;
}

/* HalGetScatterGatherList
      Creates a scatter-gather list to be using in scatter/gather DMA

   AdapterObject
      Adapter object representing the bus master or system dma controller.
   DeviceObject
      The device target for DMA.
   Mdl
      The MDL that describes the buffer to be mapped.
   CurrentVa
      The current VA in the buffer to be mapped for transfer.
   Length
      Specifies the length of data in bytes to be mapped.
   ExecutionRoutine
      A caller supplied AdapterListControl routine to be called when DMA is available.
   Context
      Context passed to the AdapterListControl routine.
   WriteToDevice
      Indicates direction of DMA operation.

   return The status of the operation.

   see HalPutScatterGatherList
*/
NTSTATUS
NTAPI
HalGetScatterGatherList(
    _In_ PDMA_ADAPTER DmaAdapter,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PMDL Mdl,
    _In_ PVOID CurrentVa,
    _In_ ULONG Length,
    _In_ PDRIVER_LIST_CONTROL ExecutionRoutine,
    _In_ PVOID Context,
    _In_ BOOLEAN WriteToDevice)
{
    return HalBuildScatterGatherList(DmaAdapter,
                                     DeviceObject,
                                     Mdl,
                                     CurrentVa,
                                     Length,
                                     ExecutionRoutine,
                                     Context,
                                     WriteToDevice,
                                     NULL,
                                     0);
}

/* HalPutScatterGatherList
      Frees a scatter-gather list allocated from HalGetScatterGatherList

   AdapterObject
      Adapter object representing the bus master or system dma controller.
   ScatterGather
      The scatter/gather list to be freed.
   WriteToDevice
      Indicates direction of DMA operation.

   return None

   see HalGetScatterGatherList
*/
VOID
NTAPI
HalPutScatterGatherList(
    _In_ PDMA_ADAPTER DmaAdapter,
    _In_ PSCATTER_GATHER_LIST ScatterGather,
    _In_ BOOLEAN WriteToDevice)
{
    PSCATTER_GATHER_CONTEXT AdapterControlContext;
    ULONG ix;

    AdapterControlContext = (PSCATTER_GATHER_CONTEXT)ScatterGather->Reserved;

    for (ix = 0; ix < ScatterGather->NumberOfElements; ix++)
    {
         IoFlushAdapterBuffers(DmaAdapter,
                               AdapterControlContext->Mdl,
                               AdapterControlContext->MapRegisterBase,
                               AdapterControlContext->CurrentVa,
                               ScatterGather->Elements[ix].Length,
                               AdapterControlContext->WriteToDevice);

         AdapterControlContext->CurrentVa += ScatterGather->Elements[ix].Length;
    }

    IoFreeMapRegisters(DmaAdapter,
                       AdapterControlContext->MapRegisterBase,
                       AdapterControlContext->MapRegisterCount);

    DPRINT("S/G DMA has finished!\n");

    ExFreePoolWithTag(AdapterControlContext, TAG_DMA);
    ExFreePoolWithTag(ScatterGather, TAG_DMA);
}

NTSTATUS
NTAPI
HalCalculateScatterGatherListSize(
    _In_ PDMA_ADAPTER DmaAdapter,
    _In_ PMDL Mdl OPTIONAL,
    _In_ PVOID CurrentVa,
    _In_ ULONG Length,
    _Out_ PULONG ScatterGatherListSize,
    _Out_ PULONG pNumberOfMapRegisters)
{
    //PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    UNIMPLEMENTED;
    ASSERT(FALSE); // HalpDbgBreakPointEx();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
HalBuildScatterGatherList(
    _In_ PDMA_ADAPTER DmaAdapter,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PMDL Mdl,
    _In_ PVOID CurrentVa,
    _In_ ULONG Length,
    _In_ PDRIVER_LIST_CONTROL ExecutionRoutine,
    _In_ PVOID Context,
    _In_ BOOLEAN WriteToDevice,
    _In_ PVOID ScatterGatherBuffer,
    _In_ ULONG ScatterGatherBufferLength)
{
    //PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    UNIMPLEMENTED;
    ASSERT(FALSE); // HalpDbgBreakPointEx();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
HalBuildMdlFromScatterGatherList(
    _In_ PDMA_ADAPTER DmaAdapter,
    _In_ PSCATTER_GATHER_LIST ScatterGather,
    _In_ PMDL OriginalMdl,
    _Out_ PMDL* TargetMdl)
{
    //PDMA_ADAPTER DmaAdapter = (PADAPTER_OBJECT)DmaAdapter;
    UNIMPLEMENTED;
    ASSERT(FALSE); // HalpDbgBreakPointEx();
    return STATUS_NOT_IMPLEMENTED;
}

/* HalpDmaInitializeEisaAdapter
       Setup DMA modes and extended modes for (E)ISA DMA adapter object.
*/
BOOLEAN
NTAPI
HalpDmaInitializeEisaAdapter(
    _In_ PADAPTER_OBJECT AdapterObject,
    _In_ PDEVICE_DESCRIPTION DeviceDescriptor)
{
    DMA_EXTENDED_MODE ExtendedMode = {{0}};
    DMA_MODE DmaMode = {{0}};
    PVOID AdapterBaseVa;
    PVOID Port;
    UCHAR Controller;
    UCHAR DmaMask;

    Controller = ((DeviceDescriptor->DmaChannel & 4) ? 2 : 1);

    if (Controller == 1)
        AdapterBaseVa = UlongToPtr(FIELD_OFFSET(EISA_CONTROL, DmaController1));
    else
        AdapterBaseVa = UlongToPtr(FIELD_OFFSET(EISA_CONTROL, DmaController2));

    AdapterObject->AdapterNumber = Controller;
    AdapterObject->ChannelNumber = (UCHAR)(DeviceDescriptor->DmaChannel & 3);
    AdapterObject->PagePort = (PUCHAR)HalpEisaPortPage[DeviceDescriptor->DmaChannel];
    AdapterObject->Width16Bits = FALSE;
    AdapterObject->AdapterBaseVa = AdapterBaseVa;

    if (HalpEisaDma)
    {
        ExtendedMode.ChannelNumber = AdapterObject->ChannelNumber;

        switch (DeviceDescriptor->DmaSpeed)
        {
            case Compatible: ExtendedMode.TimingMode = COMPATIBLE_TIMING; break;
            case TypeA:      ExtendedMode.TimingMode = TYPE_A_TIMING;     break;
            case TypeB:      ExtendedMode.TimingMode = TYPE_B_TIMING;     break;
            case TypeC:      ExtendedMode.TimingMode = BURST_TIMING;      break;
            default:
                return FALSE;
        }

        switch (DeviceDescriptor->DmaWidth)
        {
            case Width8Bits:  ExtendedMode.TransferSize = B_8BITS;  break;
            case Width16Bits: ExtendedMode.TransferSize = B_16BITS; break;
            case Width32Bits: ExtendedMode.TransferSize = B_32BITS; break;
            default:
                return FALSE;
        }

        if (Controller == 1)
        {
            Port = UlongToPtr(FIELD_OFFSET(EISA_CONTROL, DmaExtendedMode1));
            WRITE_PORT_UCHAR(Port, ExtendedMode.Byte);
        }
        else
        {
            Port = UlongToPtr(FIELD_OFFSET(EISA_CONTROL, DmaExtendedMode2));
            WRITE_PORT_UCHAR(Port, ExtendedMode.Byte);
        }
    }
    else
    {
        /* Validate setup for non-busmaster DMA adapter.
           Secondary controller supports only 16-bit transfers and main controller supports only 8-bit transfers.
           Anything else is invalid.
        */
        if (!DeviceDescriptor->Master)
        {
            if ((Controller == 2) && (DeviceDescriptor->DmaWidth == Width16Bits))
            {
                AdapterObject->Width16Bits = TRUE;
            }
            else if ((Controller != 1) || (DeviceDescriptor->DmaWidth != Width8Bits))
            {
                return FALSE;
            }
        }
    }

    DmaMode.Channel = AdapterObject->ChannelNumber;
    DmaMode.AutoInitialize = DeviceDescriptor->AutoInitialize;

    /* Set the DMA request mode.
       For (E)ISA bus master devices just unmask (enable) the DMA channel and set it to cascade mode.
       Otherwise just select the right one bases on the passed device description.
    */
    if (!DeviceDescriptor->Master)
    {
        if (DeviceDescriptor->DemandMode)
            DmaMode.RequestMode = DEMAND_REQUEST_MODE;
        else
            DmaMode.RequestMode = SINGLE_REQUEST_MODE;

        goto Exit;
    }

    DmaMode.RequestMode = CASCADE_REQUEST_MODE;
    DmaMask = (AdapterObject->ChannelNumber | DMA_CLEARMASK);

    if (Controller == 1)
    {
        /* Set the Request Data */
        _PRAGMA_WARNING_SUPPRESS(__WARNING_DEREF_NULL_PTR)
        WRITE_PORT_UCHAR(&((PDMA1_CONTROL)AdapterBaseVa)->Mode, DmaMode.Byte);

        /* Unmask DMA Channel */
        WRITE_PORT_UCHAR(&((PDMA1_CONTROL)AdapterBaseVa)->SingleMask, DmaMask);
    }
    else
    {
        /* Set the Request Data */
        WRITE_PORT_UCHAR(&((PDMA2_CONTROL)AdapterBaseVa)->Mode, DmaMode.Byte);

        /* Unmask DMA Channel */
        WRITE_PORT_UCHAR(&((PDMA2_CONTROL)AdapterBaseVa)->SingleMask, DmaMask);
    }

Exit:
    AdapterObject->AdapterMode = DmaMode;
    return TRUE;
}

/* HalpGrowMapBufferWorker
      Helper routine of HalAllocateAdapterChannel for allocating map registers at PASSIVE_LEVEL in work item.
*/
VOID
NTAPI
HalpGrowMapBufferWorker(
    _In_ PVOID DeferredContext)
{
    PGROW_WORK_ITEM WorkItem = (PGROW_WORK_ITEM)DeferredContext;
    KIRQL OldIrql;
    BOOLEAN Succeeded;

    /* Try to allocate new map registers for the adapter.
       NOTE: The NT implementation actually tries to allocate more map registers than needed as an optimization.
    */
    KeWaitForSingleObject(&HalpDmaLock, WrExecutive, KernelMode, FALSE, NULL);

    Succeeded = HalpGrowMapBuffers(WorkItem->AdapterObject->MasterAdapter,
                                  (WorkItem->NumberOfMapRegisters << PAGE_SHIFT));

    KeSetEvent(&HalpDmaLock, IO_NO_INCREMENT, FALSE);

    if (!Succeeded)
    {
        DPRINT1("HalpGrowMapBufferWorker: Succeeded is FALSE\n");
        ExFreePool(WorkItem);
        return;
    }

    /* Flush the adapter queue now that new map registers are ready.
       The easiest way to do that is to call IoFreeMapRegisters to not free any registers.
       Note that we use the magic (PVOID)2 map register base to bypass the parameter checking.
    */
    OldIrql = KfRaiseIrql(DISPATCH_LEVEL);
    IoFreeMapRegisters((PDMA_ADAPTER)WorkItem->AdapterObject, UlongToPtr(2), 0);
    KfLowerIrql(OldIrql);

    ExFreePool(WorkItem);
}

/* PUBLIC FUNCTIONS **********************************************************/

/* HalAllocateAdapterChannel
       Setup map registers for an adapter object.

   AdapterObject
      Pointer to an ADAPTER_OBJECT to set up.

   WaitContextBlock
      Context block to be used with ExecutionRoutine.

   NumberOfMapRegisters
      Number of map registers requested.

   ExecutionRoutine
      Callback to call when map registers are allocated.

   return:
      If not enough map registers can be allocated then STATUS_INSUFFICIENT_RESOURCES is returned.
      If the function succeeds or the callback is queued for later delivering then STATUS_SUCCESS is returned.
 
   see IoFreeAdapterChannel
*/
NTSTATUS
NTAPI
HalAllocateAdapterChannel(
    _In_ PDMA_ADAPTER DmaAdapter,
    _In_ PWAIT_CONTEXT_BLOCK WaitContextBlock,
    _In_ ULONG NumberOfMapRegisters,
    _In_ PDRIVER_CONTROL ExecutionRoutine)
{
    PADAPTER_OBJECT AdapterObject = (PADAPTER_OBJECT)DmaAdapter;
    PADAPTER_OBJECT MasterAdapter;
    PGROW_WORK_ITEM WorkItem;
    ULONG Index = MAXULONG;
    ULONG Result;
    KIRQL OldIrql;

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    /* Set up the wait context block in case we can't run right away. */
    WaitContextBlock->DeviceRoutine = ExecutionRoutine;
    WaitContextBlock->NumberOfMapRegisters = NumberOfMapRegisters;

    /* Returns true if queued, else returns false and sets the queue to busy */
    if (KeInsertDeviceQueue(&AdapterObject->ChannelWaitQueue, &WaitContextBlock->WaitQueueEntry))
        return STATUS_SUCCESS;

    MasterAdapter = AdapterObject->MasterAdapter;

    AdapterObject->NumberOfMapRegisters = NumberOfMapRegisters;
    AdapterObject->CurrentWcb = WaitContextBlock;

    if (NumberOfMapRegisters && AdapterObject->NeedsMapRegisters)
    {
        if (NumberOfMapRegisters > AdapterObject->MapRegistersPerChannel)
        {
            DPRINT1("HalAllocateAdapterChannel: STATUS_INSUFFICIENT_RESOURCES\n");
            AdapterObject->NumberOfMapRegisters = 0;
            IoFreeAdapterChannel(DmaAdapter);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        /* Get the map registers.

           This is partly complicated by the fact that new map registers can only be allocated at PASSIVE_LEVEL
           and we're currently at DISPATCH_LEVEL.

           The following code has two code paths:

          - If there is no adapter queued for map register allocation,
            try to see if enough contiguous map registers are present.
            In case they're we can just get them and proceed further.

          - If some adapter is already present in the queue we must respect the order of adapters
            asking for map registers and so the fast case described above can't take place.
            This case is also entered if not enough coniguous map registers are present.

            A work queue item is allocated and queued, the adapter is also queued into the master adapter queue.
            The worker routine does the job of allocating the map registers at PASSIVE_LEVEL
            and calling the ExecutionRoutine.
        */

        KeAcquireSpinLock(&MasterAdapter->SpinLock, &OldIrql);

        if (IsListEmpty(&MasterAdapter->AdapterQueue))
        {
            Index = RtlFindClearBitsAndSet(MasterAdapter->MapRegisters, NumberOfMapRegisters, 0);

            if (Index != MAXULONG)
            {
                AdapterObject->MapRegisterBase = MasterAdapter->MapRegisterBase + Index;

                if (!AdapterObject->ScatterGather)
                {
                    AdapterObject->MapRegisterBase =
                    (PROS_MAP_REGISTER_ENTRY)((ULONG_PTR)AdapterObject->MapRegisterBase | MAP_BASE_SW_SG);
                }
            }
        }

        if (Index == MAXULONG)
        {
            InsertTailList(&MasterAdapter->AdapterQueue, &AdapterObject->AdapterQueue);

            WorkItem = ExAllocatePoolWithTag(NonPagedPool, sizeof(GROW_WORK_ITEM), TAG_DMA);
            if (WorkItem)
            {
                ExInitializeWorkItem(&WorkItem->WorkQueueItem, HalpGrowMapBufferWorker, WorkItem);

                WorkItem->AdapterObject = AdapterObject;
                WorkItem->NumberOfMapRegisters = NumberOfMapRegisters;

                ExQueueWorkItem(&WorkItem->WorkQueueItem, DelayedWorkQueue);
            }

            KeReleaseSpinLock(&MasterAdapter->SpinLock, OldIrql);

            return STATUS_SUCCESS;
        }

        KeReleaseSpinLock(&MasterAdapter->SpinLock, OldIrql);
    }
    else
    {
        AdapterObject->MapRegisterBase = NULL;
        AdapterObject->NumberOfMapRegisters = 0;
    }

    AdapterObject->CurrentWcb = WaitContextBlock;

    Result = ExecutionRoutine(WaitContextBlock->DeviceObject,
                              WaitContextBlock->CurrentIrp,
                              AdapterObject->MapRegisterBase,
                              WaitContextBlock->DeviceContext);

    /* Possible return values:
     
       - KeepObject
         Don't free any resources, the ADAPTER_OBJECT is still in use
         and the caller will call IoFreeAdapterChannel later.

       - DeallocateObject
         Deallocate the map registers and release the ADAPTER_OBJECT, so someone else can use it.

       - DeallocateObjectKeepRegisters
         Release the ADAPTER_OBJECT, but hang on to the map registers. The client will later call IoFreeMapRegisters.

       NOTE:
       IoFreeAdapterChannel runs the queue, so it must be called unless the adapter object is not to be freed.
    */
    if (Result == DeallocateObject)
    {
        IoFreeAdapterChannel(DmaAdapter);
    }
    else if (Result == DeallocateObjectKeepRegisters)
    {
        AdapterObject->NumberOfMapRegisters = 0;
        IoFreeAdapterChannel(DmaAdapter);
    }

    return STATUS_SUCCESS;
}

/* HalGetAdapter
      Allocate an adapter object for DMA device.

   DeviceDescriptor
      Structure describing the attributes of the device.

   NumberOfMapRegisters
      On return filled with the maximum number of map registers
      the device driver can allocate for DMA transfer operations.

   return:
      The DMA adapter on success, NULL otherwise.
*/
PADAPTER_OBJECT
NTAPI
HalGetAdapter(
    _In_ PDEVICE_DESCRIPTION DeviceDescriptor,
    _Out_ PULONG NumberOfMapRegisters)
{
    PADAPTER_OBJECT AdapterObject = NULL;
    PVOID AdapterBaseVa = NULL;
    ULONG MapRegisters;
    ULONG MaximumLength;
    ULONG BufferSize;
    BOOLEAN IsFlag0;
    BOOLEAN IsDma32Bit;
    KIRQL OldIrql;

    DPRINT("HalGetAdapter: DeviceDescriptor %p\n", DeviceDescriptor);

    /* Validate parameters in device description */
    if (DeviceDescriptor->Version > DEVICE_DESCRIPTION_VERSION2)
    {
        DPRINT1("HalGetAdapter: Wrong Version %X\n", DeviceDescriptor->Version);
        return NULL;
    }

    if (DeviceDescriptor->Version == DEVICE_DESCRIPTION_VERSION1)
        ASSERT(DeviceDescriptor->Reserved1 == FALSE);

    if ((DeviceDescriptor->InterfaceType != Isa && DeviceDescriptor->Master != 0) ||
        (DeviceDescriptor->InterfaceType == Isa && DeviceDescriptor->DmaChannel > 7))
    {
        IsFlag0 = FALSE;
    }
    else
    {
        IsFlag0 = TRUE;
    }

    /* Disallow creating adapter for ISA/EISA DMA channel 4 since it's used
       for cascading the controllers and it's not available for software use.
    */
    if (IsFlag0 && (DeviceDescriptor->DmaChannel == 4))
        return NULL;

    if (HalpBusType == MACHINE_TYPE_EISA)
    {
        DPRINT1("HalGetAdapter: FIXME MACHINE_TYPE_EISA\n");
        ASSERT(FALSE); // HalpDbgBreakPointEx();
    }

    if (DeviceDescriptor->InterfaceType == PCIBus &&
        DeviceDescriptor->Master &&
        DeviceDescriptor->ScatterGather)
    {
        DPRINT("HalGetAdapter: Dma32BitAddresses is TRUE\n");
        DeviceDescriptor->Dma32BitAddresses = TRUE;
    }

    /* Calculate the number of map registers.
     
       - For EISA and PCI scatter/gather no map registers are needed.
       - For ISA slave scatter/gather one map register is needed.
       - For all other cases the number of map registers depends on DeviceDescriptor->MaximumLength.
    */
    MaximumLength = DeviceDescriptor->MaximumLength & (MAXULONG / 2); // 2 Gb max. length

    IsDma32Bit = DeviceDescriptor->Dma32BitAddresses;

    if (DeviceDescriptor->ScatterGather &&
        (HalpPhysicalMemoryMayAppearAbove4GB == FALSE || DeviceDescriptor->Dma64BitAddresses) &&
        (LessThan16Mb || DeviceDescriptor->InterfaceType == Eisa || DeviceDescriptor->InterfaceType == PCIBus))
    {
        MapRegisters = 0;
    }
    else
    {
        MapRegisters = BYTES_TO_PAGES(MaximumLength) + 1;

        if (MapRegisters > 16)
            MapRegisters = 16;

        if (!HalpEisaDma)
        {
            if (HalpPhysicalMemoryMayAppearAbove4GB && IsDma32Bit)
                BufferSize = MasterAdapter32.MapBufferSize;
            else
                BufferSize = MasterAdapter24.MapBufferSize;

            if (MapRegisters > ((BufferSize >> PAGE_SHIFT) / 2))
                MapRegisters = ((BufferSize >> PAGE_SHIFT) / 2);
        }

        if (DeviceDescriptor->ScatterGather && DeviceDescriptor->Master == FALSE)
            MapRegisters = 1;
    }

    if (IsFlag0)
    {
        DPRINT1("HalGetAdapter: IsFlag0 FIXME\n");
        ASSERT(FALSE); // HalpDbgBreakPointEx();
    }

    /* Now we must get ahold of the adapter object.
       For first eight ISA/EISA channels there are static adapter objects 
       that are reused and updated on succesive HalGetAdapter calls.
       In other cases a new adapter object is always created
       and it's to the DMA adapter list (HalpDmaAdapterList).
    */
    if (IsFlag0)
    {
        AdapterObject = HalpEisaAdapter[DeviceDescriptor->DmaChannel];

        if (AdapterObject &&
            AdapterObject->NeedsMapRegisters &&
            MapRegisters > AdapterObject->MapRegistersPerChannel)
        {
            AdapterObject->MapRegistersPerChannel = MapRegisters;
        }
    }

    if (!AdapterObject)
    {
        KeWaitForSingleObject(&HalpDmaLock, WrExecutive, KernelMode, FALSE, NULL);

        if (IsFlag0)
        {
            AdapterObject = HalpEisaAdapter[DeviceDescriptor->DmaChannel];

            if (AdapterObject &&
                AdapterObject->NeedsMapRegisters &&
                MapRegisters > AdapterObject->MapRegistersPerChannel)
            {
                AdapterObject->MapRegistersPerChannel = MapRegisters;
            }
        }
        else
        {
            AdapterObject = HalpAllocateAdapterEx(MapRegisters, AdapterBaseVa, IsDma32Bit);
            if (!AdapterObject)
            {
                DPRINT1("HalGetAdapter: HalpAllocateAdapterEx() failed\n");
                ASSERT(FALSE); // HalpDbgBreakPointEx();
                KeSetEvent(&HalpDmaLock, IO_NO_INCREMENT, FALSE);
                return NULL;
            }

            if (IsFlag0)
                HalpEisaAdapter[DeviceDescriptor->DmaChannel] = AdapterObject;

            if (MapRegisters)
            {
                PHALP_DMA_MASTER_ADAPTER pMasterAdapter;
                PADAPTER_OBJECT MasterAdapter;

                if (!HalpPhysicalMemoryMayAppearAbove4GB || !IsDma32Bit)
                    pMasterAdapter = &MasterAdapter24;
                else
                    pMasterAdapter = &MasterAdapter32;

                MasterAdapter = pMasterAdapter->MasterAdapter;
                AdapterObject->MapRegistersPerChannel = MapRegisters;

                if (DeviceDescriptor->Master)
                    MasterAdapter->CommittedMapRegisters += (2 * MapRegisters);
                else
                    MasterAdapter->CommittedMapRegisters += MapRegisters;

                if (MasterAdapter->CommittedMapRegisters > MasterAdapter->NumberOfMapRegisters)
                    HalpGrowMapBuffers(MasterAdapter, 0x10000);

                AdapterObject->NeedsMapRegisters = TRUE;
            }
            else
            {
                AdapterObject->NeedsMapRegisters = FALSE;

                if (DeviceDescriptor->Master)
                    AdapterObject->MapRegistersPerChannel = (BYTES_TO_PAGES(MaximumLength) + 1);
                else
                    AdapterObject->MapRegistersPerChannel = 1;
            }
        }

        KeSetEvent(&HalpDmaLock, IO_NO_INCREMENT, FALSE);
    }

    /* Setup the values in the adapter object that are common for all types of buses */
    if (DeviceDescriptor->Version >= DEVICE_DESCRIPTION_VERSION1)
        AdapterObject->IgnoreCount = DeviceDescriptor->IgnoreCount;
    else
        AdapterObject->IgnoreCount = 0;

    AdapterObject->Dma32BitAddresses = DeviceDescriptor->Dma32BitAddresses;
    AdapterObject->Dma64BitAddresses = DeviceDescriptor->Dma64BitAddresses;
    AdapterObject->ScatterGather = DeviceDescriptor->ScatterGather;
    AdapterObject->MasterDevice = DeviceDescriptor->Master;

    *NumberOfMapRegisters = AdapterObject->MapRegistersPerChannel;

    /* For non-(E)ISA adapters we have already done all the work.
       On the other hand for (E)ISA adapters we must still setup the DMA modes and prepare the controller.
    */
    if (!IsFlag0)
        goto Exit;

    if (!HalpDmaInitializeEisaAdapter(AdapterObject, DeviceDescriptor))
    {
        ObDereferenceObject(AdapterObject);
        return NULL;
    }

Exit:

    KeAcquireSpinLock(&HalpDmaAdapterListLock, &OldIrql);
    InsertTailList(&HalpDmaAdapterList, &AdapterObject->AdapterList);
    KeReleaseSpinLock(&HalpDmaAdapterListLock, OldIrql);

    return AdapterObject;
}

PVOID
NTAPI
HalAllocateCrashDumpRegisters(
    _In_ PADAPTER_OBJECT AdapterObject,
    _Inout_ PULONG NumberOfMapRegisters)
{
    UNIMPLEMENTED;
    ASSERT(FALSE); // HalpDbgBreakPointEx();
    return NULL;
}

/* EOF */
