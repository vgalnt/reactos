#ifndef _PNPIO_H
#define _PNPIO_H

#define PIP_SUBKEY_FLAG_SKIP_ERROR  1
#define PIP_SUBKEY_FLAG_DELETE_KEY  2

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
    PipEnumAssignResources,
    PipEnumGetSetDeviceStatus,
    PipEnumClearProblem,
    PipEnumInvalidateRelationsInList,
    PipEnumHaltDevice,
    PipEnumBootDevices,
    PipEnumDeviceOnly,
    PipEnumDeviceTree,
    PipEnumRootDevices,
    PipEnumInvalidateDeviceState,
    PipEnumResetDevice,
    PipEnumIoResourceChanged,
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
    UCHAR ReorderingBarrier;
    UCHAR Padded[3];
    ULONG_PTR RequestArgument;
    PKEVENT CompletionEvent;
    NTSTATUS * CompletionStatus;
} PIP_ENUM_REQUEST, *PPIP_ENUM_REQUEST;

#if defined(_M_X64)
C_ASSERT(sizeof(PIP_ENUM_REQUEST) == 0x38);
#else
C_ASSERT(sizeof(PIP_ENUM_REQUEST) == 0x20);
#endif

typedef struct _PIP_RESOURCE_REQUEST
{
    PDEVICE_OBJECT PhysicalDevice;
    ULONG Flags;
    ARBITER_REQUEST_SOURCE AllocationType;
    ULONG Priority;
    ULONG Position;
    PIO_RESOURCE_REQUIREMENTS_LIST ResourceRequirements;
    PVOID ReqList;
    PCM_RESOURCE_LIST ResourceAssignment;
    PCM_RESOURCE_LIST TranslatedResourceAssignment;
    NTSTATUS Status;
#if defined(_M_X64)
    ULONG Padding;
#endif
} PIP_RESOURCE_REQUEST, *PPIP_RESOURCE_REQUEST;

#if defined(_M_X64)
C_ASSERT(sizeof(PIP_RESOURCE_REQUEST) == 0x40);
#else
C_ASSERT(sizeof(PIP_RESOURCE_REQUEST) == 0x28);
#endif

typedef struct _PIP_ASSIGN_RESOURCES_CONTEXT
{
    ULONG DeviceCount;
    BOOLEAN IncludeFailedDevices;
    UCHAR Padded[3];
    PDEVICE_OBJECT DeviceList[1];
} PIP_ASSIGN_RESOURCES_CONTEXT, *PPIP_ASSIGN_RESOURCES_CONTEXT;

typedef BOOLEAN
(NTAPI *PIP_FUNCTION_TO_SUBKEYS)(
    _In_ HANDLE Handle,
    _In_ PUNICODE_STRING Name,
    _In_ PVOID Context
);

typedef
NTSTATUS
(NTAPI *PNP_ALLOCATE_RESOURCES_ROUTINE)(
    _In_ ULONG AllocationType,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PCM_RESOURCE_LIST CmResource
);

typedef struct _PNP_RESERVED_RESOURCES_CONTEXT
{ 
    struct _PNP_RESERVED_RESOURCES_CONTEXT * NextReservedContext;
    PDEVICE_OBJECT DeviceObject;
    PCM_RESOURCE_LIST ReservedResource;
} PNP_RESERVED_RESOURCES_CONTEXT, *PPNP_RESERVED_RESOURCES_CONTEXT; 

typedef
BOOLEAN
(NTAPI *PIP_CRITICAL_CALLBACK_VERIFY_CRITICAL_ENTRY)(
    _In_ HANDLE KeyHandle
);


//
// debug.c
//
VOID
NTAPI
IopDumpCmResourceList(
    _In_ PCM_RESOURCE_LIST CmResource
);

PCM_PARTIAL_RESOURCE_DESCRIPTOR
NTAPI
IopGetNextCmPartialDescriptor(
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor
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

PWCHAR
NTAPI
IopGetBusName(
    _In_ INTERFACE_TYPE IfType
);

//
// pnpenum.c
//
NTSTATUS
NTAPI
PipRequestDeviceAction(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIP_ENUM_TYPE RequestType,
    _In_ UCHAR ReorderingBarrier,
    _In_ ULONG_PTR RequestArgument,
    _In_ PKEVENT CompletionEvent,
    _Inout_ NTSTATUS * CompletionStatus
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
// pnpirp.c
//
NTSTATUS
NTAPI
IopQueryDeviceRelations(
    _In_ DEVICE_RELATION_TYPE RelationsType,
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PDEVICE_RELATIONS * OutPendingDeviceRelations
);

NTSTATUS
NTAPI
PpIrpQueryID(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ BUS_QUERY_ID_TYPE IdType,
    _Out_ PWCHAR *OutID
);

NTSTATUS
NTAPI
PpIrpQueryCapabilities(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PDEVICE_CAPABILITIES DeviceCapabilities
);

NTSTATUS
NTAPI
IopQueryDeviceState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PNP_DEVICE_STATE *OutState
);

NTSTATUS
NTAPI
PpIrpQueryDeviceText(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ DEVICE_TEXT_TYPE DeviceTextType,
    _In_ LCID LocaleId,
    _Out_ PWCHAR * OutDeviceText
);

NTSTATUS
NTAPI
PpIrpQueryResourceRequirements(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PIO_RESOURCE_REQUIREMENTS_LIST * IoResource
);

NTSTATUS
NTAPI
PpIrpQueryBusInformation(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PPNP_BUS_INFORMATION * OutInformation
);

//
// pnpmap.c
//
VOID
NTAPI
MapperFreeList(
    VOID
);

VOID
NTAPI
MapperConstructRootEnumTree(
    _In_ BOOLEAN IsDisableMapper
);

NTSTATUS
NTAPI
MapperProcessFirmwareTree(
    _In_ BOOLEAN IsDisableMapper
);

//
// pnpmgr.c
//
USHORT
NTAPI
IopGetBusTypeGuidIndex(
    IN LPGUID BusTypeGuid
);

NTSTATUS
NTAPI
PiGetDeviceRegistryProperty(
    IN PDEVICE_OBJECT DeviceObject,
    IN ULONG ValueType,
    IN PWSTR ValueName,
    IN PWSTR KeyName,
    OUT PVOID Buffer,
    IN PULONG BufferLength
);

NTSTATUS
NTAPI
PnpDeviceObjectToDeviceInstance(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PHANDLE DeviceInstanceHandle,
    _In_ ACCESS_MASK DesiredAccess
);

NTSTATUS
NTAPI
PpDeviceRegistration(
    _In_ PUNICODE_STRING InstancePath,
    _In_ BOOLEAN Param1,
    _In_ PUNICODE_STRING ServiceName
);

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

VOID
NTAPI
PipSetDevNodeProblem(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ ULONG Problem
);

VOID
NTAPI
PipClearDevNodeProblem(
    _In_ PDEVICE_NODE DeviceNode
);

VOID
NTAPI
PpDevNodeInsertIntoTree(
    _In_ PDEVICE_NODE ParentNode,
    _In_ PDEVICE_NODE DeviceNode
);

VOID
NTAPI
PpHotSwapUpdateRemovalPolicy(
    _In_ PDEVICE_NODE DeviceNode
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

BOOLEAN
NTAPI
IopProcessAssignResources(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ BOOLEAN IncludeFailedDevices,
    _Inout_ BOOLEAN *OutIsAssigned
);

NTSTATUS
NTAPI
IopGetDeviceResourcesFromRegistry(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ BOOLEAN ResourcesType,
    _In_ ULONG VectorType,
    _Out_ PVOID * OutResource,
    _Out_ SIZE_T * OutSize
);

NTSTATUS
NTAPI
IopAllocateBootResources(
    _In_ ULONG AllocationType,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PCM_RESOURCE_LIST CmResource
);

NTSTATUS
NTAPI
IopReportBootResources(
    _In_ ULONG AllocationType,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PCM_RESOURCE_LIST CmResource
);

//
// pnputil.c
//
NTSTATUS
NTAPI
PnpAllocateUnicodeString(
    _Out_ PUNICODE_STRING String,
    _In_ USHORT Size
);

NTSTATUS
NTAPI
PnpConcatenateUnicodeStrings(
    _Out_ PUNICODE_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString,
    _In_ PUNICODE_STRING AppendString
);

NTSTATUS
NTAPI
IopMapDeviceObjectToDeviceInstance(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PUNICODE_STRING InstancePath
);

NTSTATUS
NTAPI
IopCleanupDeviceRegistryValues(
    _In_ PUNICODE_STRING InstancePath
);

PDEVICE_OBJECT
NTAPI
IopDeviceObjectFromDeviceInstance(
    _In_ PUNICODE_STRING DeviceInstance
);

NTSTATUS
NTAPI
PipApplyFunctionToSubKeys(
    _In_opt_ HANDLE RootHandle,
    _In_opt_ PUNICODE_STRING KeyName,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ UCHAR Flags,
    _In_ PIP_FUNCTION_TO_SUBKEYS Function,
    _In_ PVOID Context
);

NTSTATUS
NTAPI
IopReplaceSeparatorWithPound(
    _Out_ PUNICODE_STRING OutString,
    _In_ PUNICODE_STRING InString
);

BOOLEAN
NTAPI
IopIsDeviceInstanceEnabled(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING Instance,
    _In_ BOOLEAN IsDisableDevice
);

#endif  /* _PNPIO_H */
