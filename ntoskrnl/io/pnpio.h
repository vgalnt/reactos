#ifndef _PNPIO_H
#define _PNPIO_H

#define PIP_SUBKEY_FLAG_SKIP_ERROR  1
#define PIP_SUBKEY_FLAG_DELETE_KEY  2

#define PIP_REENUM_TYPE_SINGLE      1
#define PIP_REENUM_TYPE_SUBTREE     2

#define IOP_RES_HANDLER_TYPE_TRANSLATOR 1
#define IOP_RES_HANDLER_TYPE_ARBITER    2
#define IOP_RES_HANDLER_TYPE_LEGACY     3
#define IOP_MAX_MAIN_RESOURCE_TYPE      15

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

typedef struct _PI_RESOURCE_TRANSLATOR_ENTRY
{
    LIST_ENTRY DeviceTranslatorList; // Link to DeviceNode->DeviceTranslatorList
    UCHAR ResourceType;
    UCHAR Padding[3];
    PTRANSLATOR_INTERFACE TranslatorInterface;
    PDEVICE_NODE DeviceNode;
} PI_RESOURCE_TRANSLATOR_ENTRY, *PPI_RESOURCE_TRANSLATOR_ENTRY;

typedef struct _PNP_REQ_LIST PNP_REQ_LIST, *PPNP_REQ_LIST;

typedef struct _PNP_RESOURCE_REQUEST
{
    PDEVICE_OBJECT PhysicalDevice;
    ULONG Flags;
    ARBITER_REQUEST_SOURCE AllocationType;
    ULONG Priority;
    ULONG Position;
    PIO_RESOURCE_REQUIREMENTS_LIST ResourceRequirements;
    PPNP_REQ_LIST ReqList;
    PCM_RESOURCE_LIST ResourceAssignment;
    PCM_RESOURCE_LIST TranslatedResourceAssignment;
    NTSTATUS Status;
#if defined(_M_X64)
    ULONG Padding;
#endif
} PNP_RESOURCE_REQUEST, *PPNP_RESOURCE_REQUEST;

#if defined(_M_X64)
C_ASSERT(sizeof(PNP_RESOURCE_REQUEST) == 0x40);
#else
C_ASSERT(sizeof(PNP_RESOURCE_REQUEST) == 0x28);
#endif

typedef struct _PNP_REQ_RESOURCE_ENTRY
{
    LIST_ENTRY Link; // Link to (PPI_RESOURCE_ARBITER_ENTRY)->ResourceList
    ULONG Count;
    PIO_RESOURCE_DESCRIPTOR IoDescriptor;
    PDEVICE_OBJECT PhysicalDevice;
    ARBITER_REQUEST_SOURCE AllocationType;
    ULONG Reserved1;
    ULONG Reserved2;
    INTERFACE_TYPE InterfaceType;
    ULONG SlotNumber;
    ULONG BusNumber;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR pCmDescriptor;
    ULONG Reserved3;
    ULONG Reserved4;
    CM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
} PNP_REQ_RESOURCE_ENTRY, *PPNP_REQ_RESOURCE_ENTRY; 

typedef struct _PNP_REQ_ALT_LIST *PPNP_REQ_ALT_LIST; 

typedef struct _PNP_REQ_DESCRIPTOR
{
    INTERFACE_TYPE InterfaceType;
    ULONG BusNumber;
    BOOLEAN IsArbitrated;
    UCHAR Padded0[3];
    PPNP_REQ_ALT_LIST AltList;
    ULONG DescNumber;
    struct _PNP_REQ_DESCRIPTOR * TranslatedReqDesc;
    PNP_REQ_RESOURCE_ENTRY ReqEntry;
    ULONG Reserved[18];
    ULONG DescriptorsCount;
    PIO_RESOURCE_DESCRIPTOR DevicePrivateIoDesc; // CmResourceTypeDevicePrivate
    union
    {
        struct _PI_RESOURCE_ARBITER_ENTRY * ArbiterEntry;
        struct _PI_RESOURCE_TRANSLATOR_ENTRY * TranslatorEntry;
    };
} PNP_REQ_DESCRIPTOR, *PPNP_REQ_DESCRIPTOR; 

typedef struct _PNP_REQ_ALT_LIST
{
    ULONG ConfigPriority;
    ULONG Priority;
    PPNP_REQ_LIST ReqList;
    ULONG ListNumber;
    ULONG CountDescriptors;
    PPNP_REQ_DESCRIPTOR ReqDescriptors[1]; // array pointers to descriptors
} PNP_REQ_ALT_LIST, *PPNP_REQ_ALT_LIST; 

typedef struct _PNP_REQ_LIST
{ 
    INTERFACE_TYPE InterfaceType;
    ULONG BusNumber;
    PPNP_RESOURCE_REQUEST ResRequest;
    PPNP_REQ_ALT_LIST AltList1;
    PPNP_REQ_ALT_LIST AltList2;
    ULONG Count;
    PPNP_REQ_ALT_LIST AltLists[1]; // array pointers to alternative lists
} PNP_REQ_LIST, *PPNP_REQ_LIST; 

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
    _In_ ARBITER_REQUEST_SOURCE AllocationType,
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

typedef union _DEVICE_CAPABILITIES_FLAGS
{
    struct {
        ULONG  DeviceD1:1;
        ULONG  DeviceD2:1;
        ULONG  LockSupported:1;
        ULONG  EjectSupported:1;
        ULONG  Removable:1;
        ULONG  DockDevice:1;
        ULONG  UniqueID:1;
        ULONG  SilentInstall:1;
        ULONG  RawDeviceOK:1;
        ULONG  SurpriseRemovalOK:1;
        ULONG  WakeFromD0:1;
        ULONG  WakeFromD1:1;
        ULONG  WakeFromD2:1;
        ULONG  WakeFromD3:1;
        ULONG  HardwareDisabled:1;
        ULONG  NonDynamic:1;
        ULONG  WarmEjectSupported:1;
        ULONG  NoDisplayInUI:1;
        ULONG  Reserved:14;
    };
    ULONG AsULONG;
} DEVICE_CAPABILITIES_FLAGS, *PDEVICE_CAPABILITIES_FLAGS;

C_ASSERT(sizeof(DEVICE_CAPABILITIES_FLAGS) == sizeof(ULONG));

typedef struct _IOPNP_DEVICE_EXTENSION
{
    PWCHAR CompatibleIdList;
    ULONG CompatibleIdListSize;
} IOPNP_DEVICE_EXTENSION, *PIOPNP_DEVICE_EXTENSION;

//=== iomgr ================================

//
// driver.c
//
NTSTATUS
NTAPI
IopInvalidDeviceRequest(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

VOID
FASTCALL
IopDisplayLoadingMessage(
    _In_ PUNICODE_STRING ServiceName
);

BOOLEAN
NTAPI
IopIsLegacyDriver(
    _In_ PDRIVER_OBJECT DriverObject
);

NTSTATUS
NTAPI
IopLoadDriver(
    _In_ HANDLE ServiceHandle,
    _In_ BOOLEAN SafeBootModeFlag,
    _In_ BOOLEAN IsFilter,
    _Out_ NTSTATUS * OutInitStatus
);

//=== pnpmgr ===============================

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

VOID
NTAPI
devnode(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ ULONG Flags,
    _In_ PUNICODE_STRING ServiceName
);

VOID
NTAPI
IopDumpReqDescriptor(
    _In_ PPNP_REQ_DESCRIPTOR Descriptor,
    _In_ ULONG Idx
);

VOID
NTAPI
IopDumpResRequest(
    _In_ PPNP_RESOURCE_REQUEST ResRequest
);

//
// pnpenum.c
//
NTSTATUS
NTAPI
PpCriticalProcessCriticalDevice(
    _In_ PDEVICE_NODE DeviceNode
);

NTSTATUS
NTAPI
IopQueryAndSaveDeviceNodeCapabilities(
    _In_ PDEVICE_NODE DeviceNode
);

NTSTATUS
NTAPI
PipCallDriverAddDevice(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ BOOLEAN IsLoadDriver,
    _In_ SERVICE_LOAD_TYPE * DriverLoadType
);

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

BOOLEAN
FASTCALL
IopInitializeBootDrivers(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock
);

VOID
FASTCALL
IopInitializeSystemDrivers(
    VOID
);

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

NTSTATUS
NTAPI
PpIrpQueryResources(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PCM_RESOURCE_LIST * OutResourceList,
    _Out_ PULONG OutSize
);

NTSTATUS
NTAPI
IopQueryLegacyBusInformation(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ GUID * OutBusTypeGuid,
    _Out_ INTERFACE_TYPE * OutInterfaceType,
    _Out_ PULONG OutBusNumber
);

NTSTATUS
NTAPI
IopQueryResourceHandlerInterface(
    _In_ ULONG InterfaceType,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ UCHAR InterfaceSpecificData,
    _Out_ PVOID * OutInterface
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

VOID
NTAPI
IopInsertLegacyBusDeviceNode(
    _In_ PDEVICE_NODE LegacyDeviceNode,
    _In_ INTERFACE_TYPE InterfaceType,
    _In_ ULONG Bus
);

VOID
NTAPI
IopMarkHalDeviceNode(
    VOID
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
    _In_ ARBITER_REQUEST_SOURCE AllocationType,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PCM_RESOURCE_LIST CmResource
);

NTSTATUS
NTAPI
IopReportBootResources(
    _In_ ARBITER_REQUEST_SOURCE AllocationType,
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
IopGetDeviceInstanceCsConfigFlags(
    _In_ PUNICODE_STRING InstanceName,
    _Out_ PULONG OutConfigFlagsValue
);

NTSTATUS
NTAPI
PipOpenServiceEnumKeys(
    _In_ PUNICODE_STRING ServiceString,
    _In_ ACCESS_MASK Aaccess,
    _Out_ PHANDLE OutHandle,
    _Out_ PHANDLE OutEnumHandle,
    _In_ BOOLEAN IsCreate
);

NTSTATUS
NTAPI
IopOpenDeviceParametersSubkey(
    _Out_ PHANDLE OutHandle,
    _In_opt_ HANDLE ParentKey,
    _In_ PUNICODE_STRING NameString,
    _In_ ACCESS_MASK Access
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

NTSTATUS
NTAPI
IopGetDriverNameFromKeyNode(
    _In_ HANDLE KeyHandle,
    _Inout_ PUNICODE_STRING OutDriverName
);

BOOLEAN
NTAPI
IopIsAnyDeviceInstanceEnabled(
    _In_ PUNICODE_STRING ServiceKeyName,
    _In_ HANDLE ServiceKeyHandle,
    _In_ BOOLEAN IsLegacyDriver
);

PIO_RESOURCE_REQUIREMENTS_LIST
NTAPI
IopCmResourcesToIoResources(
    _In_ ULONG Slot,
    _In_ PCM_RESOURCE_LIST CmResource,
    _In_ ULONG Priority
);

#endif  /* _PNPIO_H */
