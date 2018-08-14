#ifndef _PNPIO_H
#define _PNPIO_H

typedef struct _PNP_DEVICE_INSTANCE_CONTEXT
{
    PDEVICE_OBJECT DeviceObject;
    PUNICODE_STRING InstancePath;
} PNP_DEVICE_INSTANCE_CONTEXT, *PPNP_DEVICE_INSTANCE_CONTEXT;

//
// Request types for PIP_ENUM_REQUEST
//
typedef enum _PIP_ENUM_TYPE
{
    PipEnumAddBootDevices,
    PipEnumResourcesAssign,
    PipEnumGetSetDeviceStatus,
    PipEnumClearProblem,
    PipEnumInvalidateRelationsInList,
    PipEnumHaltDevice,
    PipEnumBootProcess,
    PipEnumInvalidateRelations,
    PipEnumInvalidateBusRelations,
    PipEnumInitPnpServices,
    PipEnumInvalidateDeviceState,
    PipEnumResetDevice,
    PipEnumResourceChange,
    PipEnumSystemHiveLimitChange,
    PipEnumSetProblem,
    PipEnumShutdownPnpDevices,
    PipEnumStartDevice,
    PipEnumStartSystemDevices
} PIP_ENUM_TYPE;

typedef struct _PIP_ENUM_REQUEST
{
    LIST_ENTRY RequestLink;
    PDEVICE_OBJECT DeviceObject;
    PIP_ENUM_TYPE RequestType;
    UCHAR Param1;
    UCHAR Padded[3];
    PVOID Param2;
    PKEVENT Event;
    NTSTATUS * OutStatus;
} PIP_ENUM_REQUEST, *PPIP_ENUM_REQUEST;

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

VOID
NTAPI
IopDumpResourceRequirementsList(
    _In_ PIO_RESOURCE_REQUIREMENTS_LIST IoResource
);

VOID
NTAPI
IopDumpIoResourceDescriptor(
    _In_ PSTR Tab,
    _In_ PIO_RESOURCE_DESCRIPTOR Descriptor
);


//
// pnpenum.c
//
NTSTATUS
NTAPI
PipRequestDeviceAction(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIP_ENUM_TYPE RequestType,
    _In_ UCHAR Param1,
    _In_ PVOID Param2,
    _In_ PKEVENT Event,
    _Inout_ NTSTATUS * OutStatus
);

//
// pnpinit.c
//
NTSTATUS NTAPI IopPortInitialize();
NTSTATUS NTAPI IopMemInitialize();
NTSTATUS NTAPI IopDmaInitialize();
NTSTATUS NTAPI IopIrqInitialize();
NTSTATUS NTAPI IopBusNumberInitialize();

//
// pnpnode.c
//
VOID
NTAPI
PpDevNodeLockTree(
    _In_ ULONG LockLevel
);

VOID
NTAPI
PpDevNodeUnlockTree(
    _In_ ULONG LockLevel
);

VOID
NTAPI
PipSetDevNodeState(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ PNP_DEVNODE_STATE NewState,
    _Out_ PNP_DEVNODE_STATE *OutPreviousState
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

//
// pnputil.c
//
NTSTATUS
NTAPI
IopMapDeviceObjectToDeviceInstance(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PUNICODE_STRING InstancePath
);

PDEVICE_OBJECT
NTAPI
IopDeviceObjectFromDeviceInstance(
    _In_ PUNICODE_STRING DeviceInstance
);

#endif  /* _PNPIO_H */
