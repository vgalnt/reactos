/*
 * PROJECT:     ACPI driver for NT 5.x
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Main header file
 * COPYRIGHT:   Copyright 2019, 2023 Vadim Galyant <vgal@rambler.ru>
 */

#ifndef _ACPI_H_
#define _ACPI_H_

#include <ntifs.h>
#include <drivers/acpi/acpi.h> //sdk/include/reactos/drivers/acpi/acpi.h
#include <ndk/rtlfuncs.h>
#include <arbiter.h>           //sdk/lib/drivers/arbiter/arbiter.h
#include <stdio.h>
#include <initguid.h>
#include <wdmguid.h>
#include <wmilib.h>
#include <wmiguid.h>
#include <poclass.h>
#include <acpiioct.h>
#include "amli.h"


/* STRUCTURES ***************************************************************/

/* ACPI TABLES **************************************************************/

typedef struct _MAPIC
{
    DESCRIPTION_HEADER Header;
    ULONG LocalAPICAddress;
    ULONG Flags;
    ULONG APICTables[1];
} MAPIC, *PMAPIC;

typedef struct _ACPIInformation
{
    PRSDT RootSystemDescTable;
    PFADT FixedACPIDescTable;
    PFACS FirmwareACPIControlStructure;
    PDSDT DiffSystemDescTable;
    PMAPIC MultipleApicTable;
    PULONG GlobalLock;
    LIST_ENTRY GlobalLockQueue;
    KSPIN_LOCK GlobalLockQueueLock;
    PVOID GlobalLockOwnerContext;
    ULONG GlobalLockOwnerDepth;
    BOOLEAN ACPIOnly;
    UCHAR Pad0[3];
    ULONG PM1a_BLK;
    ULONG PM1b_BLK;
    ULONG PM1a_CTRL_BLK;
    ULONG PM1b_CTRL_BLK;
    ULONG PM2_CTRL_BLK;
    ULONG PM_TMR;
    ULONG GP0_BLK;
    ULONG GP0_ENABLE;
    UCHAR GP0_LEN;
    UCHAR Pad1;
    USHORT Gpe0Size;
    ULONG GP1_BLK;
    ULONG GP1_ENABLE;
    UCHAR GP1_LEN;
    UCHAR Pad2;
    USHORT Gpe1Size;
    USHORT GP1_Base_Index;
    USHORT GpeSize;
    ULONG SMI_CMD;
    USHORT pm1_en_bits;
    USHORT pm1_wake_mask;
    USHORT pm1_wake_status;
    USHORT c2_latency;
    USHORT c3_latency;
    UCHAR Pad3[2];
    ULONG ACPI_Flags;
    ULONG ACPI_Capabilities;
    BOOLEAN Dockable;
    UCHAR Pad4[3];
} ACPI_INFORMATION, *PACPI_INFORMATION;

typedef struct _RSDTELEMENT
{
    ULONG Flags;
    PVOID Handle;
    PVOID Address;
} RSDTELEMENT, *PRSDTELEMENT;

typedef struct _RSDTINFORMATION
{
    ULONG NumElements;
    RSDTELEMENT Tables[1];
} RSDTINFORMATION, *PRSDTINFORMATION;

/* ACPI DRIVER **************************************************************/

typedef enum
{
    Stopped = 0x0,
    Inactive = 0x1,
    Started = 0x2,
    Removed = 0x3,
    SurpriseRemoved = 0x4,
    Invalid = 0x5,
} ACPI_DEVICE_STATE;

typedef enum
{
    AcpiPowerRequestDevice = 0x0,
    AcpiPowerRequestSystem = 0x1,
    AcpiPowerRequestWaitWake = 0x2,
    AcpiPowerRequestWarmEject = 0x3,
    AcpiPowerRequestSynchronize = 0x4,
    AcpiPowerRequestMaximum = 0x5,
} ACPI_POWER_REQUEST_TYPE;

typedef struct _ACPI_HAL_DISPATCH_TABLE
{
    ULONG Signature;
    ULONG Version;
    PVOID Function1;
    PVOID Function2;
    PVOID Function3;
} ACPI_HAL_DISPATCH_TABLE, *PACPI_HAL_DISPATCH_TABLE;

typedef struct _ACPI_POWER_DEVICE_NODE
{
    LIST_ENTRY ListEntry;
    union
    {
        ULONGLONG Flags;
        struct
        {
            ULONGLONG Present : 1;
            ULONGLONG Initialized : 1;
            ULONGLONG StatusUnknown : 1;
            ULONGLONG On : 1;
            ULONGLONG OverrideOn : 1;
            ULONGLONG OverrideOff : 1;
            ULONGLONG AlwaysOn : 1;
            ULONGLONG AlwaysOff : 1;
            ULONGLONG Reserved1 : 5;
            ULONGLONG Failed : 1;
            ULONGLONG HibernatePath : 1;
            ULONGLONG Reserved2 : 49;
        } UFlags;
    };
    ULONG UseCounts;
    PAMLI_NAME_SPACE_OBJECT PowerObject;
    CHAR ResourceOrder;
    UCHAR Pad[3];
    SYSTEM_POWER_STATE SystemLevel;
    LIST_ENTRY DevicePowerListHead;
    LONG WorkDone;
    PAMLI_NAME_SPACE_OBJECT PowerOnObject;
    PAMLI_NAME_SPACE_OBJECT PowerOffObject;
    PAMLI_NAME_SPACE_OBJECT PowerStaObject;
} ACPI_POWER_DEVICE_NODE, *PACPI_POWER_DEVICE_NODE;

typedef struct _ACPI_DEVICE_POWER_NODE
{
    struct _ACPI_DEVICE_POWER_NODE* Next;
    PACPI_POWER_DEVICE_NODE PowerNode;
    SYSTEM_POWER_STATE SystemState;
    DEVICE_POWER_STATE AssociatedDeviceState;
    CHAR WakePowerResource;
    struct _DEVICE_EXTENSION* DeviceExtension;
    LIST_ENTRY DevicePowerListEntry;
} ACPI_DEVICE_POWER_NODE, *PACPI_DEVICE_POWER_NODE;

typedef struct _ACPI_POWER_REQUEST
{
    LIST_ENTRY ListEntry;
    LIST_ENTRY SerialListEntry;
    ULONG Signature;
    struct _DEVICE_EXTENSION* DeviceExtension;
    ACPI_POWER_REQUEST_TYPE RequestType;
    CHAR FailedOnce;
    union
    {
        struct
        {
            ULONG Flags;
            DEVICE_POWER_STATE DevicePowerState;
        } DevicePowerRequest;
        struct
        {
            SYSTEM_POWER_STATE SystemPowerState;
            POWER_ACTION SystemPowerAction;
        } SystemPowerRequest;
        struct
        {
            ULONG Flags;
            SYSTEM_POWER_STATE SystemPowerState;
        } WaitWakeRequest;
        struct
        {
            ULONG Flags;
            SYSTEM_POWER_STATE EjectPowerState;
        } EjectPowerRequest;
        struct
        {
            ULONG Flags;
        } SynchronizePowerRequest;
        struct
        {
            ULONG Delayed : 1;
            ULONG NoQueue : 1;
            ULONG LockDevice : 1;
            ULONG UnlockDevice : 1;
            ULONG LockHiber : 1;
            ULONG UnlockHiber : 1;
            ULONG HasCancel : 1;
            ULONG UpdateProfile : 1;
            ULONG SyncQueue : 1;
            ULONG Reserved : 23;
        } UFlags;
    } u;
    VOID (NTAPI* CallBack)(VOID);
    PVOID Context;
    LONG WorkDone;
    ULONG NextWorkDone;
    AMLI_OBJECT_DATA ResultData;
    NTSTATUS Status;
} ACPI_POWER_REQUEST, *PACPI_POWER_REQUEST;

typedef struct _ACPI_POWER_INFO
{
    PVOID Context;
    DEVICE_POWER_STATE PowerState;
    PDEVICE_NOTIFY_CALLBACK DeviceNotifyHandler;
    PVOID HandlerContext;
    PACPI_DEVICE_POWER_NODE PowerNode[4];
    PAMLI_NAME_SPACE_OBJECT PowerObject[5];
    ULONG WakeBit;
    DEVICE_POWER_STATE DevicePowerMatrix[7];
    SYSTEM_POWER_STATE SystemWakeLevel;
    DEVICE_POWER_STATE DeviceWakeLevel;
    DEVICE_POWER_STATE DesiredPowerState;
    ULONG WakeSupportCount;
    LIST_ENTRY WakeSupportList;
    PACPI_POWER_REQUEST CurrentPowerRequest;
    LIST_ENTRY PowerRequestListEntry;
    ULONG SupportDeviceD1 : 1;
    ULONG SupportDeviceD2 : 1;
    ULONG SupportWakeFromD0 : 1;
    ULONG SupportWakeFromD1 : 1;
    ULONG SupportWakeFromD2 : 1;
    ULONG SupportWakeFromD3 : 1;
    ULONG Reserved : 26;
} ACPI_POWER_INFO, *PACPI_POWER_INFO;

typedef struct _IRP_DISPATCH_TABLE
{
    PDRIVER_DISPATCH CreateClose;
    PDRIVER_DISPATCH DeviceControl;
    PDRIVER_DISPATCH PnpStartDevice;
    PDRIVER_DISPATCH* Pnp;
    PDRIVER_DISPATCH* Power;
    PDRIVER_DISPATCH SystemControl;
    PDRIVER_DISPATCH Other;
    VOID (NTAPI* Worker)(struct _DEVICE_EXTENSION*, ULONG);
} IRP_DISPATCH_TABLE, *PIRP_DISPATCH_TABLE;

typedef struct _EXTENSION_WORKER
{
    ULONG PendingEvents;
    LIST_ENTRY Link;
} EXTENSION_WORKER, *PEXTENSION_WORKER;

typedef struct _BUTTON_EXTENSION
{
    EXTENSION_WORKER WorkQueue;
    KSPIN_LOCK SpinLock;
    CHAR LidState;
    union
    {
        ULONG Events;
        struct
        {
            ULONG Power_Button : 1;
            ULONG Sleep_Button : 1;
            ULONG Lid_Switch : 1;
            ULONG Reserved : 28;
            ULONG Wake_Capable : 1;
        } UEvents;
    };
    union
    {
        ULONG Capabilities;
        struct
        {
          ULONG Power_Button : 1;
          ULONG Sleep_Button : 1;
          ULONG Lid_Switch : 1;
          ULONG Reserved : 28;
          ULONG Wake_Capable : 1;
        } UCapabilities;
    };
} BUTTON_EXTENSION, *PBUTTON_EXTENSION;

typedef struct _PROCESSOR_DEVICE_EXTENSION
{
    EXTENSION_WORKER WorkQueue;
    PCHAR CompatibleID;
    ULONG ProcessorIndex;
} PROCESSOR_DEVICE_EXTENSION, *PPROCESSOR_DEVICE_EXTENSION;

typedef struct _MODULE_DEVICE_EXTENSION
{
    EXTENSION_WORKER WorkQueue;
    BOOLEAN ArbitersNeeded;
    UCHAR Pad[3];
    struct _ACPI_ARBITER_INSTANCE* Arbiters[3];
} MODULE_DEVICE_EXTENSION, *PMODULE_DEVICE_EXTENSION;

typedef struct _ACPI_THERMAL_INFO
{
    THERMAL_INFORMATION Header;
    ULONG ActiveCoolingLevel;
    ULONG CoolingMode;
    PAMLI_NAME_SPACE_OBJECT NsObjects[0xA];
    PAMLI_NAME_SPACE_OBJECT CurrentTemperatureMethod;
    AMLI_OBJECT_DATA TempatureData;
} ACPI_THERMAL_INFO, *PACPI_THERMAL_INFO;

typedef struct _THERMAL_EXTENSION
{
    EXTENSION_WORKER WorkQueue;
    KSPIN_LOCK SpinLock;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG Cooling : 1;
            ULONG Temp : 1;
            ULONG Trip : 1;
            ULONG Mode : 1;
            ULONG Init : 1;
            ULONG Reserved : 24;
            ULONG Wait : 1;
            ULONG Busy : 1;
            ULONG Loop : 1;
        } UFlags;
    };
    PACPI_THERMAL_INFO Info;
    PWMILIB_CONTEXT WmilibContext;
} THERMAL_EXTENSION, *PTHERMAL_EXTENSION;

typedef struct _WORK_QUEUE_CONTEXT
{
    WORK_QUEUE_ITEM Item;
    PDEVICE_OBJECT DeviceObject;
    PIRP Irp;
} WORK_QUEUE_CONTEXT, *PWORK_QUEUE_CONTEXT;

typedef struct _FDO_DEVICE_EXTENSION
{
    WORK_QUEUE_CONTEXT WorkContext;
    PKINTERRUPT InterruptObject;
    union
    {
        ULONG Pm1Status;
        struct
        {
            ULONG Tmr_Sts : 1;
            ULONG Reserved1 : 3;
            ULONG Bm_Sts : 1;
            ULONG Gbl_Sts : 1;
            ULONG Reserved2 : 2;
            ULONG PwrBtn_Sts : 1;
            ULONG SlpBtn_Sts : 1;
            ULONG Rtc_Sts : 1;
            ULONG Reserved3 : 4;
            ULONG Wak_Sts : 1;
            ULONG Gpe_Sts : 1;
            ULONG Reserved4 : 14;
            ULONG Dpc_Sts : 1;
        } UPm1Status;
    };
    KDPC InterruptDpc;
} FDO_DEVICE_EXTENSION, *PFDO_DEVICE_EXTENSION;

typedef struct _FILTER_DEVICE_EXTENSION
{
    WORK_QUEUE_CONTEXT WorkContext;
    PBUS_INTERFACE_STANDARD Interface;
} FILTER_DEVICE_EXTENSION, *PFILTER_DEVICE_EXTENSION;

typedef struct _PDO_DEVICE_EXTENSION
{
    WORK_QUEUE_CONTEXT WorkContext;
} PDO_DEVICE_EXTENSION, *PPDO_DEVICE_EXTENSION;

typedef enum
{
    PDS_UPDATE_DEFAULT = 0x1,
    PDS_UPDATE_ON_REMOVE = 0x2,
    PDS_UPDATE_ON_INTERFACE = 0x3,
    PDS_UPDATE_ON_EJECT = 0x4,
} PROFILE_DEPARTURE_STYLE;

typedef enum
{
    IS_UNKNOWN = 0x0,
    IS_ISOLATED = 0x1,
    IS_ISOLATION_DROPPED = 0x2,
} ISOLATION_STATE;

typedef struct _DOCK_EXTENSION
{
    EXTENSION_WORKER WorkQueue;
    struct _DEVICE_EXTENSION* CorrospondingAcpiDevice;
    PROFILE_DEPARTURE_STYLE ProfileDepartureStyle;
    ULONG InterfaceReferenceCount;
    ISOLATION_STATE IsolationState;
} DOCK_EXTENSION, *PDOCK_EXTENSION;

typedef struct _DEVICE_EXTENSION
{
    union
    {
        ULONGLONG Flags;
        struct
        {
            ULONGLONG Type_Never_Present : 1;
            ULONGLONG Type_Not_Present : 1;
            ULONGLONG Type_Removed : 1;
            ULONGLONG Type_Not_Found : 1;
            ULONGLONG Type_Fdo : 1;
            ULONGLONG Type_Pdo : 1;
            ULONGLONG Type_Filter : 1;
            ULONGLONG Type_Surprise_Removed : 1;
            ULONGLONG Type_Not_Enumerated : 1;
            ULONGLONG Reserved1 : 7;
            ULONGLONG Cap_Wake : 1;
            ULONGLONG Cap_Raw : 1;
            ULONGLONG Cap_Button : 1;
            ULONGLONG Cap_Always_PS0 : 1;
            ULONGLONG Cap_No_Filter : 1;
            ULONGLONG Cap_No_Stop : 1;
            ULONGLONG Cap_No_Override : 1;
            ULONGLONG Cap_ISA : 1;
            ULONGLONG Cap_EIO : 1;
            ULONGLONG Cap_PCI : 1;
            ULONGLONG Cap_Serial : 1;
            ULONGLONG Cap_Thermal_Zone : 1;
            ULONGLONG Cap_LinkNode : 1;
            ULONGLONG Cap_No_Show_in_UI : 1;
            ULONGLONG Cap_Never_show_in_UI : 1;
            ULONGLONG Cap_Start_in_D3 : 1;
            ULONGLONG Cap_PCI_Device : 1;
            ULONGLONG Cap_PIC_Device : 1;
            ULONGLONG Cap_Unattached_Dock : 1;
            ULONGLONG Cap_No_Disable_Wake : 1;
            ULONGLONG Cap_Processor : 1;
            ULONGLONG Cap_Container : 1;
            ULONGLONG Cap_PCI_Bar_Target : 1;
            ULONGLONG Cap_No_Remove_or_Eject : 1;
            ULONGLONG Reserved2 : 1;
            ULONGLONG Prop_Rebuild_Children : 1;
            ULONGLONG Prop_Invalid_Relations : 1;
            ULONGLONG Prop_Unloading : 1;
            ULONGLONG Prop_Address : 1;
            ULONGLONG Prop_HID : 1;
            ULONGLONG Prop_UID : 1;
            ULONGLONG Prop_Fixed_HID : 1;
            ULONGLONG Prop_Fixed_UID : 1;
            ULONGLONG Prop_Failed_Init : 1;
            ULONGLONG Prop_Srs_Present : 1;
            ULONGLONG Prop_No_Object : 1;
            ULONGLONG Prop_Exclusive : 1;
            ULONGLONG Prop_Ran_INI : 1;
            ULONGLONG Prop_Device_Enabled : 1;
            ULONGLONG Prop_Device_Failed : 1;
            ULONGLONG Prop_Acpi_Power : 1;
            ULONGLONG Prop_Dock : 1;
            ULONGLONG Prop_Built_Power_Table : 1;
            ULONGLONG Prop_Has_PME : 1;
            ULONGLONG Prop_No_Lid_Action : 1;
            ULONGLONG Prop_Fixed_Address : 1;
            ULONGLONG Prop_Callback : 1;
            ULONGLONG Prop_Fixed_CiD : 1;
        } UFlags;
    };
    ULONG Signature;
    ULONG DebugFlags;
    PIRP_DISPATCH_TABLE DispatchTable;
    union
    {
        FDO_DEVICE_EXTENSION Fdo;
        PDO_DEVICE_EXTENSION Pdo;
        FILTER_DEVICE_EXTENSION Filter;
        WORK_QUEUE_CONTEXT WorkContext;
    };
    union
    {
        EXTENSION_WORKER WorkQueue;
        BUTTON_EXTENSION Button;
        PROCESSOR_DEVICE_EXTENSION Processor;
        MODULE_DEVICE_EXTENSION Module;
        THERMAL_EXTENSION Thermal;
        DOCK_EXTENSION Dock;
    };
    ACPI_DEVICE_STATE DeviceState;
    ACPI_DEVICE_STATE PreviousState;
    ACPI_POWER_INFO PowerInfo;
    union
    {
        PCHAR DeviceID;
        PCHAR Address;
    };
    PCHAR InstanceID;
    PCM_RESOURCE_LIST ResourceList;
    PAMLI_OBJECT_DATA PnpResourceList;
    LONG OutstandingIrpCount;
    LONG ReferenceCount;
    LONG HibernatePathCount;
    PKEVENT RemoveEvent;
    PAMLI_NAME_SPACE_OBJECT AcpiObject;
    PDEVICE_OBJECT DeviceObject;
    PDEVICE_OBJECT TargetDeviceObject;
    PDEVICE_OBJECT PhysicalDeviceObject;
    struct _DEVICE_EXTENSION* ParentExtension;
    LIST_ENTRY ChildDeviceList;
    LIST_ENTRY SiblingDeviceList;
    LIST_ENTRY EjectDeviceHead;
    LIST_ENTRY EjectDeviceList;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

typedef struct _ACPI_BUILD_REQUEST
{
    LIST_ENTRY Link;
    ULONG Signature;
    ULONG Flags;
    LONG WorkDone;
    ULONG BuildReserved0;
    ULONG BuildReserved1;
    PVOID Context;
    NTSTATUS Status;
    PAMLI_NAME_SPACE_OBJECT ChildObject;
    PVOID CallBack;
    PVOID CallBackContext;
    union
    {
        struct
        {
            PLIST_ENTRY ListHead;
            PVOID Context;
            ULONG Reserved1;
        } Synchronize;
        struct
        {
            AMLI_OBJECT_DATA Data;
        } Device;
        struct
        {
            PVOID Context;
            ULONG Flags;
        } RunMethod;
    };
    union
    {
        PLIST_ENTRY ListHeadForInsert;
        PVOID DataBuff;
    };
} ACPI_BUILD_REQUEST, *PACPI_BUILD_REQUEST;

typedef struct _ACPI_EXT_LIST_ENUM_DATA
{
    PLIST_ENTRY List;
    PKSPIN_LOCK SpinLock;
    KIRQL Irql;
    UCHAR Pad[3];
    struct _DEVICE_EXTENSION* DeviceExtension;
    ULONG Offset;
    ULONG ExtListEnum2;
} ACPI_EXT_LIST_ENUM_DATA, *PACPI_EXT_LIST_ENUM_DATA;

typedef struct _ACPI_INTERNAL_DEVICE_FLAG
{
    PCHAR StringId;
    //UCHAR Pad[4];
    ULONGLONG Flags;
} ACPI_INTERNAL_DEVICE_FLAG, *PACPI_INTERNAL_DEVICE_FLAG;

typedef struct _ACPI_INTERNAL_DEVICE
{
    PCHAR StringId;
    PIRP_DISPATCH_TABLE DispatchTable;
} ACPI_INTERNAL_DEVICE, *PACPI_INTERNAL_DEVICE;

typedef struct _ACPI_WAIT_CONTEXT
{
    KEVENT Event;
    NTSTATUS Status;
} ACPI_WAIT_CONTEXT, *PACPI_WAIT_CONTEXT;

typedef struct _IS_PCI_BUS_CONTEXT
{
    PAMLI_NAME_SPACE_OBJECT NsObject;
    ULONG Flags;
    PCHAR HidId;
    PCHAR CidId;
    PVOID Adr;
    BOOLEAN IsPciDevice;
    UCHAR Pad[3];
    LONG RefCount;
    PVOID CallBack;
    PVOID CallBackContext;
    BOOLEAN* OutIsBusAsync;
    UCHAR Buffer[0x40]; // FIXME
} IS_PCI_BUS_CONTEXT, *PIS_PCI_BUS_CONTEXT;

typedef struct _ACPI_PSW_CONTEXT
{
    LIST_ENTRY Link;
    PDEVICE_EXTENSION DeviceExtension;
    BOOLEAN IsEnable;
    BOOLEAN Pad[3];
    ULONG Count;
    PVOID CallBack;
    PVOID Context;
} ACPI_PSW_CONTEXT, *PACPI_PSW_CONTEXT;

/* PM_DISPATCH STRUCTURES ***************************************************/

typedef struct _HALP_STATE_DATA
{
    UCHAR Data0;
    UCHAR Data1;
    UCHAR Data2;
} HALP_STATE_DATA, *PHALP_STATE_DATA;

typedef VOID
(NTAPI * PHAL_ACPI_TIMER_INIT)(
    _In_ PULONG TimerPort,
    _In_ BOOLEAN TimerValExt
);

typedef VOID
(NTAPI * PHAL_ACPI_MACHINE_STATE_INIT)(
    _In_ ULONG Par1,
    _In_ PHALP_STATE_DATA StateData,
    _Out_ ULONG* OutInterruptModel
);

typedef ULONG
(NTAPI * PHAL_ACPI_QUERY_FLAGS)(
    VOID
);

typedef UCHAR
(NTAPI * PHAL_ACPI_PIC_STATE_INTACT)(
    VOID
);

typedef VOID
(NTAPI * PHAL_RESTORE_INT_CONTROLLER_STATE)(
    VOID
);

typedef ULONG
(NTAPI * PHAL_PCI_INTERFACE_READ_CONFIG)(
    _In_ PBUS_HANDLER RootBusHandler,
    _In_ ULONG BusNumber,
    _In_ PCI_SLOT_NUMBER SlotNumber,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length
);

typedef ULONG
(NTAPI * PHAL_PCI_INTERFACE_WRITE_CONFIG)(
    _In_ PBUS_HANDLER RootBusHandler,
    _In_ ULONG BusNumber,
    _In_ PCI_SLOT_NUMBER SlotNumber,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length
);

typedef VOID
(NTAPI * PHAL_SET_VECTOR_STATE)(
    _In_ ULONG Vector,
    _In_ ULONG Par2
);

typedef ULONG
(NTAPI * PHAL_GET_APIC_VERSION)(
    _In_ ULONG Par1
);

typedef VOID
(NTAPI * PHAL_SET_MAX_LEGACY_PCI_BUS_NUMBER)(
    _In_ ULONG Par1
);

typedef BOOLEAN
(NTAPI * PHAL_IS_VECTOR_VALID)(
    _In_ ULONG Vector
);

typedef struct _ACPI_PM_DISPATCH_TABLE
{
    ULONG Signature;
    ULONG Version;
    PHAL_ACPI_TIMER_INIT HalAcpiTimerInit;                          // HaliAcpiTimerInit
    PVOID HalAcpiTimerInterrupt;
    PHAL_ACPI_MACHINE_STATE_INIT HalAcpiMachineStateInit;           // HaliAcpiMachineStateInit
    PHAL_ACPI_QUERY_FLAGS HalAcpiQueryFlags;                        // HaliAcpiQueryFlags
    PHAL_ACPI_PIC_STATE_INTACT HalAcpiPicStateIntact;               // HalpAcpiPicStateIntact
    PHAL_RESTORE_INT_CONTROLLER_STATE HalRestoreIntControllerState; // HalpRestoreInterruptControllerState
    PHAL_PCI_INTERFACE_READ_CONFIG HalPciInterfaceReadConfig;       // HaliPciInterfaceReadConfig
    PHAL_PCI_INTERFACE_WRITE_CONFIG HalPciInterfaceWriteConfig;     // HaliPciInterfaceWriteConfig
    PHAL_SET_VECTOR_STATE HalSetVectorState;                        // HaliSetVectorState
    PHAL_GET_APIC_VERSION HalGetApicVersion;                        // HalpGetApicVersion
    PHAL_SET_MAX_LEGACY_PCI_BUS_NUMBER HalSetMaxLegacyPciBusNumber; // HaliSetMaxLegacyPciBusNumber
    PHAL_IS_VECTOR_VALID HalIsVectorValid;                          // HaliIsVectorValid
} ACPI_PM_DISPATCH_TABLE, *PACPI_PM_DISPATCH_TABLE;

typedef NTSTATUS
(NTAPI* PPOWER_PROCESS_DISPATCH)(
    _In_ PACPI_POWER_REQUEST
);

/* ACPI TABLES **************************************************************/

/* Names within the namespace are 4 bytes long */
#define ACPI_NAMESEG_SIZE               4     // Fixed by ACPI spec

/* Sizes for ACPI table headers */
#define ACPI_OEM_ID_SIZE                6
#define ACPI_OEM_TABLE_ID_SIZE          8

/* Master ACPI Table Header.
   This common header is used by all ACPI tables except the RSDP and FACS.
*/
typedef struct _ACPI_TABLE_HEADER
{
    CHAR Signature[ACPI_NAMESEG_SIZE];        // ASCII table signature
    ULONG Length;                             // Length of table in bytes, including this header
    UCHAR Revision;                           // ACPI Specification minor version number
    UCHAR Checksum;                           // To make sum of entire table == 0
    CHAR OemId[ACPI_OEM_ID_SIZE];             // ASCII OEM identification
    CHAR OemTableId[ACPI_OEM_TABLE_ID_SIZE];  // ASCII OEM table identification
    ULONG OemRevision;                        // OEM revision number
    CHAR AslCompilerId[ACPI_NAMESEG_SIZE];    // ASCII ASL compiler vendor ID
    ULONG AslCompilerRevision;                // ASL compiler version
} ACPI_TABLE_HEADER, *PACPI_TABLE_HEADER;

/* Generic subtable header (used in MADT, SRAT, etc.) */
typedef struct _ACPI_SUBTABLE_HEADER
{
    UCHAR Type;
    UCHAR Length;
} ACPI_SUBTABLE_HEADER, *PACPI_SUBTABLE_HEADER;

/* Multiple APIC Description Table (MADT). Table 5-17 (ACPI 3.0) */

/* Values for MADT subtable type in ACPI_SUBTABLE_HEADER */
enum AcpiMadtType
{
    ACPI_MADT_TYPE_LOCAL_APIC               = 0,
    ACPI_MADT_TYPE_IO_APIC                  = 1,
    ACPI_MADT_TYPE_INTERRUPT_OVERRIDE       = 2,
    ACPI_MADT_TYPE_NMI_SOURCE               = 3,
    ACPI_MADT_TYPE_LOCAL_APIC_NMI           = 4,
    ACPI_MADT_TYPE_LOCAL_APIC_OVERRIDE      = 5,
    ACPI_MADT_TYPE_IO_SAPIC                 = 6,
    ACPI_MADT_TYPE_LOCAL_SAPIC              = 7,
    ACPI_MADT_TYPE_INTERRUPT_SOURCE         = 8,
    ACPI_MADT_TYPE_LOCAL_X2APIC             = 9,
    ACPI_MADT_TYPE_LOCAL_X2APIC_NMI         = 10,
    ACPI_MADT_TYPE_GENERIC_INTERRUPT        = 11,
    ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR      = 12,
    ACPI_MADT_TYPE_GENERIC_MSI_FRAME        = 13,
    ACPI_MADT_TYPE_GENERIC_REDISTRIBUTOR    = 14,
    ACPI_MADT_TYPE_GENERIC_TRANSLATOR       = 15,
    ACPI_MADT_TYPE_RESERVED                 = 16 // 16 and greater are reserved
};

/* MADT Subtables, correspond to Type in ACPI_SUBTABLE_HEADER */

/* MADT Local APIC flags */
#define ACPI_MADT_ENABLED  1 // Processor is usable if set

/* MADT MPS INTI flags (IntiFlags). Table 5-24 (ACPI 3.0) */
#define ACPI_MADT_POLARITY_CONFORMS     0
#define ACPI_MADT_POLARITY_ACTIVE_HIGH  1
#define ACPI_MADT_POLARITY_RESERVED     2
#define ACPI_MADT_POLARITY_ACTIVE_LOW   3
#define ACPI_MADT_POLARITY_MASK         (3)      // Polarity of APIC I/O input signals

#define ACPI_MADT_TRIGGER_CONFORMS      (0)
#define ACPI_MADT_TRIGGER_EDGE          (1 << 2)
#define ACPI_MADT_TRIGGER_RESERVED      (2 << 2)
#define ACPI_MADT_TRIGGER_LEVEL         (3 << 2)
#define ACPI_MADT_TRIGGER_MASK          (3 << 2) // Trigger mode of APIC input signals

/* 0: Processor Local APIC */
typedef struct _ACPI_MADT_LOCAL_APIC
{
    ACPI_SUBTABLE_HEADER Header;
    UCHAR ProcessorId;          // ACPI processor id
    UCHAR Id;                   // Processor's local APIC id
    ULONG LapicFlags;
} ACPI_MADT_LOCAL_APIC, *PACPI_MADT_LOCAL_APIC;

/* 1: IO APIC */
typedef struct _ACPI_MADT_IO_APIC
{
    ACPI_SUBTABLE_HEADER Header;
    UCHAR Id;                   // I/O APIC ID
    UCHAR Reserved;             // Reserved - must be zero
    ULONG Address;              // APIC physical address
    ULONG GlobalIrqBase;        // Global system interrupt where INTI lines start
} ACPI_MADT_IO_APIC, *PACPI_MADT_IO_APIC;

/* 2: Interrupt Override. Table 5-23 (ACPI 3.0) */
#include <pshpack1.h>
typedef struct _ACPI_MADT_INTERRUPT_OVERRIDE
{
    ACPI_SUBTABLE_HEADER Header;
    UCHAR Bus;                  // 0 - ISA
    UCHAR SourceIrq;            // Interrupt source (IRQ)
    ULONG GlobalIrq;            // Global system interrupt
    USHORT IntiFlags;
} ACPI_MADT_INTERRUPT_OVERRIDE, *PACPI_MADT_INTERRUPT_OVERRIDE;
#include <poppack.h>

/* 3: NMI Source */
typedef struct _ACPI_MADT_NMI_SOURCE
{
    ACPI_SUBTABLE_HEADER Header;
    USHORT IntiFlags;
    ULONG GlobalIrq;            // Global system interrupt
} ACPI_MADT_NMI_SOURCE, *PACPI_MADT_NMI_SOURCE;

/* 4: Local APIC NMI */
typedef struct _ACPI_MADT_LOCAL_APIC_NMI
{
    ACPI_SUBTABLE_HEADER Header;
    UCHAR ProcessorId;          // ACPI processor id
    USHORT IntiFlags;
    UCHAR Lint;                 // LINTn to which NMI is connected
} ACPI_MADT_LOCAL_APIC_NMI;

/* 7: Local SAPIC */

typedef struct _ACPI_MADT_LOCAL_SAPIC
{
    ACPI_SUBTABLE_HEADER Header;
    UCHAR ProcessorId;        // ACPI processor id
    UCHAR Id;                 // SAPIC ID
    UCHAR Eid;                // SAPIC EID
    UCHAR Reserved[3];        // Reserved, must be zero
    ULONG LapicFlags;
    ULONG Uid;                // Numeric UID - ACPI 3.0
    CHAR UidString[1];        // String UID  - ACPI 3.0

} ACPI_MADT_LOCAL_SAPIC, *PACPI_MADT_LOCAL_SAPIC;

/* Values for PCATCompat flag */
#define ACPI_MADT_MULTIPLE_APIC  0
#define ACPI_MADT_DUAL_PIC       1

typedef struct _ACPI_TABLE_MADT
{
    ACPI_TABLE_HEADER Header;   // Common ACPI table header
    ULONG Address;              // Physical address of local APIC
    ULONG Flags;
} ACPI_TABLE_MADT, *PACPI_TABLE_MADT;

/* ARBITER STRUCTURES *******************************************************/

typedef struct _ACPI_VECTOR_BLOCK
{
    union
    {
        struct
        {
            ULONG Vector;
            UCHAR Count;
            UCHAR TempCount;
            UCHAR Flags;
            UCHAR TempFlags;
        } Entry;
        struct
        {
            ULONG Token;
            struct _ACPI_VECTOR_BLOCK* Next;
        } Chain;
    };
} ACPI_VECTOR_BLOCK, *PACPI_VECTOR_BLOCK;

typedef struct _ARBITER_EXTENSION
{
    LIST_ENTRY LinkNodeHead;
    PAMLI_NAME_SPACE_OBJECT CurrentLinkNode;
    PINT_ROUTE_INTERFACE_STANDARD InterruptRouting;
    ULONG LastPciIrqIndex;
    ULONGLONG LastPciIrq[0xA];
} ARBITER_EXTENSION, *PARBITER_EXTENSION;

/* RESOURCE DATA STRUCTURES *************************************************/

#include <pshpack1.h>

typedef struct _ACPI_RESOURCE_DATA_TYPE
{
    union
    {
        struct
        {
            union
            {
                struct
                {
                    UCHAR Length :3;
                    UCHAR Name :4;
                    UCHAR Type :1;
                };
                UCHAR Tag;
            };
            UCHAR Data[];
        } Small;
        struct
        {
            union
            {
                struct
                {
                    UCHAR Name :7;
                    UCHAR Type :1;
                };
                UCHAR Tag;
            };
            USHORT Length;
            UCHAR Data[1];
        } Large;
    };
} ACPI_RESOURCE_DATA_TYPE, *PACPI_RESOURCE_DATA_TYPE;

typedef struct _ACPI_WORD_ADDRESS_SPACE_DESCRIPTOR
{
    union
    {
        struct
        {
            UCHAR Name :7;
            UCHAR Type :1;
        };
        UCHAR Tag;
    };
    USHORT Length;
    UCHAR ResourceType;
    UCHAR GeneralFlags;
    UCHAR SpecificFlags;
    USHORT Granularity;
    USHORT Minimum;
    USHORT Maximum;
    USHORT Offset;
    USHORT AddressLength;
    UCHAR ResourceSourceIndex; // Optional
    CHAR ResourceSource[]; // Optional
} ACPI_WORD_ADDRESS_SPACE_DESCRIPTOR, *PACPI_WORD_ADDRESS_SPACE_DESCRIPTOR;

typedef struct _ACPI_DWORD_ADDRESS_SPACE_DESCRIPTOR
{
    union
    {
        struct
        {
            UCHAR Name :7;
            UCHAR Type :1;
        };
        UCHAR Tag;
    };
    USHORT Length;
    UCHAR ResourceType;
    UCHAR GeneralFlags;
    UCHAR SpecificFlags;
    ULONG Granularity;
    ULONG Minimum;
    ULONG Maximum;
    ULONG Offset;
    ULONG AddressLength;
    UCHAR ResourceSourceIndex; // Optional
    CHAR ResourceSource[]; // Optional
} ACPI_DWORD_ADDRESS_SPACE_DESCRIPTOR, *PACPI_DWORD_ADDRESS_SPACE_DESCRIPTOR;

typedef struct _ACPI_QWORD_ADDRESS_SPACE_DESCRIPTOR
{
    union
    {
        struct
        {
            UCHAR Name :7;
            UCHAR Type :1;
        };
        UCHAR Tag;
    };
    USHORT Length;
    UCHAR ResourceType;
    UCHAR GeneralFlags;
    UCHAR SpecificFlags;
    ULONGLONG Granularity;
    ULONGLONG Minimum;
    ULONGLONG Maximum;
    ULONGLONG Offset;
    ULONGLONG AddressLength;
    UCHAR ResourceSourceIndex; // Optional
    CHAR ResourceSource[]; // Optional
} ACPI_QWORD_ADDRESS_SPACE_DESCRIPTOR, *PACPI_QWORD_ADDRESS_SPACE_DESCRIPTOR;

typedef struct _ACPI_IO_PORT_DESCRIPTOR
{
    union
    {
        struct
        {
            UCHAR Length :3;
            UCHAR Name :4;
            UCHAR Type :1;
        };
        UCHAR Tag;
    };
    UCHAR DecodingBitness :1;
    UCHAR Reserved :7;
    USHORT Minimum;
    USHORT Maximum;
    UCHAR Alignment;
    UCHAR RangeLength;
} ACPI_IO_PORT_DESCRIPTOR, *PACPI_IO_PORT_DESCRIPTOR;

typedef struct _ACPI_IO_PORT_10_DESCRIPTOR
{
    union
    {
        struct
        {
            UCHAR Length :3;
            UCHAR Name :4;
            UCHAR Type :1;
        };
        UCHAR Tag;
    };
    USHORT BaseAddress;
    UCHAR RangeLength;
} ACPI_IO_PORT_10_DESCRIPTOR, *PACPI_IO_PORT_10_DESCRIPTOR;

typedef struct _ACPI_FIXED_MEMORY32_DESCRIPTOR
{
    union
    {
        struct
        {
            UCHAR Name :7;
            UCHAR Type :1;
        };
        UCHAR Tag;
    };
    USHORT Length;
    struct
    {
        UCHAR Writeable :1;
        UCHAR Reserved :7;
    };
    ULONG BaseAddress;
    ULONG RangeLength;
} ACPI_FIXED_MEMORY32_DESCRIPTOR, *PACPI_FIXED_MEMORY32_DESCRIPTOR;

typedef struct _ACPI_IRQ_DESCRIPTOR
{
    union
    {
        struct
        {
            UCHAR Length :3;
            UCHAR Name :4;
            UCHAR Type :1;
        };
        UCHAR Tag;
    };
    USHORT IrqMask;
    struct
    {
        UCHAR IntMode :1;
        UCHAR Reserved0 :2;
        UCHAR IntPolarity :1;
        UCHAR IntSharable :1;
        UCHAR Reserved1 :3;
    };
} ACPI_IRQ_DESCRIPTOR, *PACPI_IRQ_DESCRIPTOR;

typedef struct _ACPI_DMA_DESCRIPTOR
{
    union
    {
        struct
        {
            UCHAR Length :3;
            UCHAR Name :4;
            UCHAR Type :1;
        };
        UCHAR Tag;
    };
    UCHAR ChannelMask;
    struct
    {
        UCHAR TransferType :2;
        UCHAR IsBusMaster :1;
        UCHAR NotUsed :2;
        UCHAR SpeedSupported :2;
        UCHAR Reserved :1;
    };
} ACPI_DMA_DESCRIPTOR, *PACPI_DMA_DESCRIPTOR;

typedef struct _ACPI_EXTENDED_IRQ_DESCRIPTOR
{
    union
    {
        struct
        {
            UCHAR Name :7;
            UCHAR Type :1;
        };
        UCHAR Tag;
    };
    USHORT Length;
    UCHAR VectorFlags;
    UCHAR TableLength;
    ULONG IntNumber[1]; // [TableLength]
    //...
    //UCHAR ResourceSourceIndex; // Optional
    //CHAR ResourceSource[]; // Optional

} ACPI_EXTENDED_IRQ_DESCRIPTOR, *PACPI_EXTENDED_IRQ_DESCRIPTOR;

#include <poppack.h>

typedef struct _ACPI_FILTER_COMPLETION_CONTEXT
{
    PDEVICE_OBJECT DeviceObject;
    PIRP Irp;
    PVOID CallBack;
    UCHAR Param5;
    UCHAR Param6;
    UCHAR Param7;
    UCHAR Param8;
    PIO_WORKITEM WorkItem;
    PVOID CallBackContext;
} ACPI_FILTER_COMPLETION_CONTEXT, *PACPI_FILTER_COMPLETION_CONTEXT;

typedef struct _ACPI_LINK_NODE
{
    LIST_ENTRY List;
    ULONG ReferenceCount;
    LONG TempRefCount;
    PAMLI_NAME_SPACE_OBJECT NameSpaceObject;
    ULONGLONG CurrentIrq;
    ULONGLONG TempIrq;
    UCHAR Flags;
    UCHAR Pad[3];
    SINGLE_LIST_ENTRY AttachedDevices;
} ACPI_LINK_NODE, *PACPI_LINK_NODE;

typedef struct _SET_LINK_NODE_IRQ
{
    PAMLI_NAME_SPACE_OBJECT NsObject;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PVOID DataBuff;
    PVOID IrqTag;
    ULONG Phase;
    LONG ReferenceCount;
    AMLI_OBJECT_DATA DataArgs;
    PVOID CallBack;
    PVOID CallBackContext;
} SET_LINK_NODE_IRQ, *PSET_LINK_NODE_IRQ;

/* Headless Terminal ********************************************************/
// From ntoskrnl/include/internal/hdl.h // FIXME

typedef enum _HEADLESS_CMD
{
    HeadlessCmdEnableTerminal = 1,
    HeadlessCmdCheckForReboot,
    HeadlessCmdPutString,
    HeadlessCmdClearDisplay,
    HeadlessCmdClearToEndOfDisplay,
    HeadlessCmdClearToEndOfLine,
    HeadlessCmdDisplayAttributesOff,
    HeadlessCmdDisplayInverseVideo,
    HeadlessCmdSetColor,
    HeadlessCmdPositionCursor,
    HeadlessCmdTerminalPoll,
    HeadlessCmdGetByte,
    HeadlessCmdGetLine,
    HeadlessCmdStartBugCheck,
    HeadlessCmdDoBugCheckProcessing,
    HeadlessCmdQueryInformation,
    HeadlessCmdAddLogEntry,
    HeadlessCmdDisplayLog,
    HeadlessCmdSetBlueScreenData,
    HeadlessCmdSendBlueScreenData,
    HeadlessCmdQueryGUID,
    HeadlessCmdPutData
} HEADLESS_CMD, *PHEADLESS_CMD;

typedef enum _HEADLESS_TERM_PORT_TYPE
{
    HeadlessUndefinedPortType = 0,
    HeadlessSerialPort
} HEADLESS_TERM_PORT_TYPE, *PHEADLESS_TERM_PORT_TYPE;

typedef enum _HEADLESS_TERM_SERIAL_PORT
{
    SerialPortUndefined = 0,
    ComPort1,
    ComPort2,
    ComPort3,
    ComPort4
} HEADLESS_TERM_SERIAL_PORT, *PHEADLESS_TERM_SERIAL_PORT;

typedef struct _HEADLESS_RSP_QUERY_INFO
{
    HEADLESS_TERM_PORT_TYPE PortType;
    union
    {
        struct
        {
            BOOLEAN TerminalAttached;
            BOOLEAN UsedBiosSettings;
            HEADLESS_TERM_SERIAL_PORT TerminalPort;
            PUCHAR TerminalPortBaseAddress;
            ULONG TerminalBaudRate;
            UCHAR TerminalType;
        } Serial;
    };
} HEADLESS_RSP_QUERY_INFO, *PHEADLESS_RSP_QUERY_INFO;

NTSTATUS
NTAPI
HeadlessDispatch(
    IN HEADLESS_CMD Command,
    IN PVOID InputBuffer,
    IN SIZE_T InputBufferSize,
    OUT PVOID OutputBuffer,
    OUT PSIZE_T OutputBufferSize
);

// FIXME (from winnt.h)

typedef struct _SYSTEM_POWER_LEVEL {
  BOOLEAN Enable;
  UCHAR Spare[3];
  ULONG BatteryLevel;
  POWER_ACTION_POLICY PowerPolicy;
  SYSTEM_POWER_STATE MinSystemState;
} SYSTEM_POWER_LEVEL, *PSYSTEM_POWER_LEVEL;

typedef struct _SYSTEM_POWER_POLICY {
  ULONG Revision;
  POWER_ACTION_POLICY PowerButton;
  POWER_ACTION_POLICY SleepButton;
  POWER_ACTION_POLICY LidClose;
  SYSTEM_POWER_STATE LidOpenWake;
  ULONG Reserved;
  POWER_ACTION_POLICY Idle;
  ULONG IdleTimeout;
  UCHAR IdleSensitivity;
  UCHAR DynamicThrottle;
  UCHAR Spare2[2];
  SYSTEM_POWER_STATE MinSleep;
  SYSTEM_POWER_STATE MaxSleep;
  SYSTEM_POWER_STATE ReducedLatencySleep;
  ULONG WinLogonFlags;
  ULONG Spare3;
  ULONG DozeS4Timeout;
  ULONG BroadcastCapacityResolution;
  SYSTEM_POWER_LEVEL DischargePolicy[NUM_DISCHARGE_POLICIES];
  ULONG VideoTimeout;
  BOOLEAN VideoDimDisplay;
  ULONG VideoReserved[3];
  ULONG SpindownTimeout;
  BOOLEAN OptimizeForPower;
  UCHAR FanThrottleTolerance;
  UCHAR ForcedThrottle;
  UCHAR MinThrottle;
  POWER_ACTION_POLICY OverThrottled;
} SYSTEM_POWER_POLICY, *PSYSTEM_POWER_POLICY;

/* FUNCTIONS ****************************************************************/

#ifndef Add2Ptr
  #define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#endif

typedef USHORT
(NTAPI* PACPI_READ_REGISTER)(
    _In_ ULONG RegType,
    _In_ ULONG Size
);

typedef VOID
(NTAPI* PACPI_WRITE_REGISTER)(
    _In_ ULONG RegType,
    _In_ ULONG Size,
    _In_ USHORT Value
);

typedef NTSTATUS
(NTAPI * PACPI_BUILD_DISPATCH)(
    _In_ PACPI_BUILD_REQUEST BuildRequest
);

typedef VOID
(NTAPI * PHAL_ACPI_TIMER_INIT)(
    _In_ PULONG TimerPort,
    _In_ BOOLEAN TimerValExt
);

typedef NTSTATUS
(NTAPI* PACPI_IRP_COMPLETION_ROUTINE)(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context,
    _In_ BOOLEAN Param4
);

/* acpiinit.c */
NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

PRSDT
NTAPI
ACPILoadFindRSDT(
    VOID
);

NTSTATUS
NTAPI
ACPILoadProcessRSDT(
    VOID
);

NTSTATUS
NTAPI
ACPILoadProcessFADT(
    _In_ PFADT Fadt
);

NTSTATUS
__cdecl
ACPICallBackLoad(
    _In_ int Param1,
    _In_ int Param2
);

NTSTATUS
__cdecl
ACPICallBackUnload(
    _In_ int Param1,
    _In_ int Param2
);

NTSTATUS
__cdecl
ACPITableNotifyFreeObject(
    _In_ int Param1,
    _In_ int Param2,
    _In_ int Param3
);

NTSTATUS
__cdecl
NotifyHandler(
    _In_ ULONG EventType,
    _In_ ULONG Notify,
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject
);

NTSTATUS
__cdecl
OSNotifyCreate(
    _In_ ULONG Type,
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject
);

NTSTATUS
__cdecl
OSNotifyFatalError(
    _In_ int Param1,
    _In_ int Param2,
    _In_ int Param3,
    _In_ int Param4
);

USHORT
NTAPI
DefPortReadAcpiRegister(
    _In_ ULONG RegType,
    _In_ ULONG Size
);

VOID
NTAPI
DefPortWriteAcpiRegister(
    _In_ ULONG RegType,
    _In_ ULONG Size,
    _In_ USHORT Value
);

VOID
NTAPI
ACPIEnableInitializeACPI(
    _In_ BOOLEAN IsNotRevertAffinity
);

VOID
NTAPI
OSQueueWorkItem(
    _In_ PWORK_QUEUE_ITEM WorkQueueItem
);

PCHAR
NTAPI
ACPIAmliNameObject(
    _In_ PAMLI_NAME_SPACE_OBJECT AcpiObject
);

NTSTATUS
NTAPI
AcpiInitIrqArbiter(
    _In_ PDEVICE_OBJECT DeviceObject
);

NTSTATUS
NTAPI
DisableLinkNodesAsync(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ PVOID Callback,
    _In_ PVOID WaitContext
);

NTSTATUS
NTAPI
GetVectorProperties(
    _In_ ULONG InVector,
    _Out_ UCHAR* OutFlags
);

NTSTATUS
NTAPI
AcpiArbCrackPRT(
    _In_ PDEVICE_OBJECT Pdo,
    _Out_ PAMLI_NAME_SPACE_OBJECT* OutLinkNode,
    _Out_ ULONG* OutVector
);

NTSTATUS
NTAPI
GetIsaVectorFlags(
    _In_ ULONG InVector,
    _Out_ UCHAR* OutFlags
);

VOID
NTAPI
CLEAR_PM1_STATUS_BITS(
    _In_ ULONG Value
);

USHORT
NTAPI
READ_PM1_STATUS(
    VOID
);

VOID
NTAPI
WRITE_PM1_CONTROL(
    _In_ USHORT Value,
    _In_ BOOLEAN Param2,
    _In_ UCHAR Flags
);

VOID
NTAPI
WRITE_PM1_ENABLE(
    _In_ USHORT Value
);

USHORT
NTAPI
ACPIReadGpeStatusRegister(
    _In_ ULONG Size
);

NTSTATUS
NTAPI
ACPIBuildRunMethodRequest(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID CallBack,
    _In_ PVOID CallBackContext,
    _In_ PVOID Context,
    _In_ ULONG Param5,
    _In_ BOOLEAN IsInsertDpc
);

PACPI_POWER_INFO
NTAPI
OSPowerFindPowerInfo(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject
);

NTSTATUS
NTAPI
ACPIBuildDeviceExtension(
    _In_ PAMLI_NAME_SPACE_OBJECT AcpiObject,
    _In_ PDEVICE_EXTENSION ParentDeviceExtension,
    _Out_ PDEVICE_EXTENSION* OutDeviceExtension
);

VOID
NTAPI
ACPIGpeEnableDisableEvents(
    _In_ BOOLEAN IsEnableEvents
);

/* dispatch.c */
NTSTATUS
NTAPI
ACPIDispatchIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

VOID
NTAPI
ACPIFilterFastIoDetachCallback(
    _In_ PDEVICE_OBJECT SourceDevice,
    _In_ PDEVICE_OBJECT TargetDevice
);

VOID
NTAPI
ACPIInitHalDispatchTable(
     VOID
);

NTSTATUS NTAPI ACPIIrpDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI ACPIDispatchForwardIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI ACPIDispatchIrpSuccess(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI ACPIDispatchWmiLog(PDEVICE_OBJECT DeviceObject, PIRP Irp);

NTSTATUS NTAPI ACPIRootIrpStartDevice(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI ACPIRootIrpQueryRemoveOrStopDevice(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI ACPIRootIrpRemoveDevice(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI ACPIRootIrpCancelRemoveOrStopDevice(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI ACPIRootIrpStopDevice(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI ACPIRootIrpQueryDeviceRelations(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI ACPIRootIrpQueryInterface(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI ACPIRootIrpQueryCapabilities(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI ACPIFilterIrpDeviceUsageNotification(PDEVICE_OBJECT DeviceObject, PIRP Irp);

NTSTATUS NTAPI ACPIDispatchIrpInvalid(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpStartDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpUnhandled(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI ACPIBusIrpQueryRemoveOrStopDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpRemoveDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpCancelRemoveOrStopDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpStopDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpQueryDeviceRelations(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpQueryInterface(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpQueryCapabilities(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpQueryResources(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpQueryResourceRequirements(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpEject(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpSetLock(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpQueryId(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpQueryPnpDeviceState(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpQueryBusInformation(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpDeviceUsageNotification(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpSurpriseRemoval(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI ACPIWakeWaitIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI ACPIDispatchForwardPowerIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI ACPIRootIrpSetPower(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI ACPIRootIrpQueryPower(PDEVICE_OBJECT DeviceObject, PIRP Irp);

NTSTATUS NTAPI ACPIDispatchPowerIrpUnhandled(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpSetPower(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIBusIrpQueryPower(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI ACPIInternalDeviceQueryDeviceRelations(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIInternalDeviceQueryCapabilities(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIInternalDeviceClockIrpStartDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI ACPIDispatchPowerIrpInvalid(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIDispatchPowerIrpSuccess(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI ACPIButtonDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIButtonStartDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPICMPowerButtonStart(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPICMButtonSetPower(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPICMSleepButtonStart(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI ACPIThermalFanStartDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIThermalDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIThermalStartDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIThermalWmi(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
VOID NTAPI ACPIThermalWorker(_In_ struct _DEVICE_EXTENSION* DeviceExtension, _In_ ULONG Param2);

NTSTATUS NTAPI ACPICMLidStart(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPICMLidSetPower(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
VOID NTAPI ACPICMLidWorker(_In_ struct _DEVICE_EXTENSION* DeviceExtension, _In_ ULONG Param2);

NTSTATUS NTAPI ACPIDockIrpStartDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIDockIrpRemoveDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIDockIrpQueryDeviceRelations(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIDockIrpQueryInterface(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIDockIrpQueryCapabilities(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIDockIrpEject(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIDockIrpSetLock(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIDockIrpQueryID(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIDockIrpQueryPnpDeviceState(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIDockIrpSetPower(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIDockIrpQueryPower(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI ACPIProcessorDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIProcessorStartDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI ACPIFilterIrpStartDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI ACPIFilterIrpRemoveDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIFilterIrpStopDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIFilterIrpQueryDeviceRelations(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIFilterIrpQueryInterface(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIFilterIrpQueryCapabilities(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIFilterIrpEject(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIFilterIrpSetLock(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIFilterIrpQueryId(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIFilterIrpQueryPnpDeviceState(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIFilterIrpSurpriseRemoval(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI ACPIFilterIrpSetPower(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ACPIFilterIrpQueryPower(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI ACPIBuildProcessGenericComplete(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessRunMethodPhaseCheckSta(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessRunMethodPhaseCheckBridge(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessRunMethodPhaseRunMethod(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessRunMethodPhaseRecurse(_In_ PACPI_BUILD_REQUEST BuildRequest);

NTSTATUS NTAPI ACPIBuildProcessDeviceFailure(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessDevicePhaseAdrOrHid(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessDevicePhaseAdr(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessDevicePhaseHid(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessDevicePhaseUid(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessDevicePhaseCid(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessDevicePhaseSta(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessDeviceGenericEvalStrict(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessDevicePhaseEjd(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessDevicePhasePrw(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessDevicePhasePr0(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessDevicePhasePr1(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessDevicePhasePr2(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessDevicePhaseCrs(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessDeviceGenericEval(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessDevicePhasePsc(_In_ PACPI_BUILD_REQUEST BuildRequest);

NTSTATUS NTAPI ACPIBuildProcessPowerResourceFailure(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessPowerResourcePhase0(_In_ PACPI_BUILD_REQUEST BuildRequest);
NTSTATUS NTAPI ACPIBuildProcessPowerResourcePhase1(_In_ PACPI_BUILD_REQUEST BuildRequest);

NTSTATUS NTAPI ACPIBuildProcessThermalZonePhase0(_In_ PACPI_BUILD_REQUEST BuildRequest);

NTSTATUS NTAPI ACPIDevicePowerProcessInvalid(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessForward(_In_ PACPI_POWER_REQUEST Request);

NTSTATUS NTAPI ACPIDevicePowerProcessPhase0DeviceSubPhase1(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase0SystemSubPhase1(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase0DeviceSubPhase2(_In_ PACPI_POWER_REQUEST Request);

NTSTATUS NTAPI ACPIDevicePowerProcessPhase1DeviceSubPhase1(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase1DeviceSubPhase2(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase1DeviceSubPhase3(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase1DeviceSubPhase4(_In_ PACPI_POWER_REQUEST Request);

NTSTATUS NTAPI ACPIDevicePowerProcessPhase2SystemSubPhase1(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase2SystemSubPhase2(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase2SystemSubPhase3(_In_ PACPI_POWER_REQUEST Request);

NTSTATUS NTAPI ACPIDevicePowerProcessPhase5DeviceSubPhase1(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase5SystemSubPhase1(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase5WarmEjectSubPhase1(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase5DeviceSubPhase2(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase5SystemSubPhase2(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase5WarmEjectSubPhase2(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase5DeviceSubPhase3(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase5SystemSubPhase3(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase5DeviceSubPhase4(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase5SystemSubPhase4(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase5DeviceSubPhase5(_In_ PACPI_POWER_REQUEST Request);
NTSTATUS NTAPI ACPIDevicePowerProcessPhase5DeviceSubPhase6(_In_ PACPI_POWER_REQUEST Request);

ULONGLONG
NTAPI
ACPIInternalUpdateFlags(
    _In_ ULONGLONG* FlagsForUpdating,
    _In_ ULONGLONG InputFlags,
    _In_ BOOLEAN IsResetFlags
);

VOID
NTAPI
ACPIBuildDeviceDpc(
    _In_ PKDPC Dpc,
    _In_ PVOID DeferredContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
);

BOOLEAN
NTAPI
ACPIInitialize(
    _In_ PDEVICE_OBJECT DeviceObject
);

NTSTATUS
NTAPI
ACPIBuildSynchronizationRequest(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID CallBack,
    _In_ PKEVENT Event,
    _In_ PLIST_ENTRY BuildDeviceList,
    _In_ BOOLEAN IsAddDpc
);

NTSTATUS
NTAPI
ACPIGet(
    _In_ PVOID Context,
    _In_ ULONG NameSeg,
    _In_ ULONG Flags,
    _In_ PVOID SimpleArgumentBuff,
    _In_ ULONG SimpleArgumentSize,
    _In_ PVOID CallBack,
    _In_ PVOID CallBackContext,
    _Out_ PVOID* OutDataBuff,
    _Out_ ULONG* OutDataLen);

VOID
NTAPI
ACPIDevicePowerDpc(
    _In_ PKDPC Dpc,
    _In_ PVOID DeferredContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
);

VOID
NTAPI
ACPIBuildProcessQueueList(
    VOID
);

NTSTATUS
NTAPI
ACPIBuildProcessGenericList(
    _In_ PLIST_ENTRY GenericList,
    _In_ PACPI_BUILD_DISPATCH* BuildDispatch
);

NTSTATUS
NTAPI
ACPIBuildProcessSynchronizationList(
    _In_ PLIST_ENTRY SynchronizationList
);

NTSTATUS
NTAPI
PnpBiosResourcesToNtResources(
    _In_ PVOID Data,
    _In_ ULONG Param2,
    _Out_ PIO_RESOURCE_REQUIREMENTS_LIST* OutIoResource
);

NTSTATUS
NTAPI
EnableDisableRegions(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ BOOLEAN IsEnable
);

NTSTATUS
NTAPI
ACPIInternalSendSynchronousIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIO_STACK_LOCATION InIoStack,
    _In_ ULONG_PTR* OutInformation
);

NTSTATUS
NTAPI
ACPIInternalGetDeviceCapabilities(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PDEVICE_CAPABILITIES Capabilities
);

BOOLEAN
NTAPI
IsPciBus(
    _In_ PDEVICE_OBJECT DeviceObject
);

NTSTATUS
NTAPI
ACPIInitStartDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PCM_RESOURCE_LIST AllocatedResources,
    _In_ PVOID Callback,
    _In_ PVOID Context,
    _In_ PIRP Irp
);

VOID
NTAPI
ACPIWriteGpeEnableRegister(
    _In_ ULONG Size,
    _In_ UCHAR Value
);

NTSTATUS
NTAPI
PnpDeviceBiosResourcesToNtResources(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID Data,
    _In_ ULONG Param3,
    _Out_ PIO_RESOURCE_REQUIREMENTS_LIST* OutIoResource
);

NTSTATUS
NTAPI
ACPIRangeSubtract(
    _Inout_ PIO_RESOURCE_REQUIREMENTS_LIST* OutIoResource,
    _In_ PCM_RESOURCE_LIST CmResource
);

NTSTATUS
NTAPI
ACPIDeviceInternalDeviceRequest(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ DEVICE_POWER_STATE DeviceState,
    _In_ PVOID CallBack,
    _In_ PVOID Context,
    _In_ ULONG Flags
);

VOID
NTAPI
ACPIThermalLoop(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ ULONG InFlags
);

NTSTATUS
NTAPI
PnpIoResourceListToCmResourceList(
    _In_ PIO_RESOURCE_REQUIREMENTS_LIST IoResource,
    _Out_ PCM_RESOURCE_LIST* OutCmResource
);

NTSTATUS
NTAPI
ACPIInternalRegisterPowerCallBack(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PCALLBACK_FUNCTION CallbackFunction
);

NTSTATUS
NTAPI
IsPciBusAsync(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ PVOID CallBack,
    _In_ PVOID CallBackContext,
    _In_ BOOLEAN* OutIsBusAsync
);

VOID
NTAPI
ACPIWakeRemoveDevicesAndUpdate(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PLIST_ENTRY InList
);

VOID
NTAPI
ACPIWriteGpeStatusRegister(
    _In_ ULONG Size,
    _In_ UCHAR Value
);

VOID
NTAPI
ACPIDeviceCompleteRequest(
    _In_ PACPI_POWER_REQUEST Request
);

ULONG
NTAPI
ACPIGpeIndexToGpeRegister(
    _In_ ULONG GpeIndex
);

ULONG
NTAPI
ACPIGpeRegisterToGpeIndex(
    _In_ ULONG ix,
    _In_ ULONG Bit
);

VOID
NTAPI
ACPIInterruptDispatchEventDpc(
    _In_ PKDPC Dpc,
    _In_ PVOID DeferredContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
);

VOID
NTAPI
RosDumpCmResources(
    _In_ PCM_RESOURCE_LIST CmResource,
    _In_ ULONG DebugLevel
);

/* registry.c */
VOID
NTAPI
ACPIInitReadRegistryKeys(
    VOID
);

NTSTATUS
NTAPI
OSCloseHandle(
    _In_ HANDLE Handle
);

NTSTATUS
NTAPI
OSOpenUnicodeHandle(
    _In_ PUNICODE_STRING Name,
    _In_ HANDLE ParentKeyHandle,
    _In_ PHANDLE KeyHandle
);

NTSTATUS
NTAPI
OSOpenHandle(
    _In_ PSZ NameString,
    _In_ HANDLE ParentKeyHandle,
    _In_ PHANDLE KeyHandle
);

NTSTATUS
NTAPI
OSReadRegValue(
    _In_ PSZ SourceString,
    _In_ HANDLE Handle,
    _In_ PVOID ValueEntry,
    _Out_ ULONG *OutMaximumLength
);

NTSTATUS
NTAPI
OSReadAcpiConfigurationData(
    _Out_ PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64* OutKeyInfo
);

NTSTATUS
NTAPI
OSGetRegistryValue(
    _In_ HANDLE KeyHandle,
    _In_ PWSTR NameString,
    _In_ PVOID* OutValue
);

BOOLEAN
NTAPI
ACPIRegReadAMLRegistryEntry(
    _In_ PDESCRIPTION_HEADER* OutTableHeader,
    _In_ BOOLEAN IsNeedUnmap
);

VOID
NTAPI
ACPIRegDumpAcpiTables(
    VOID
);

#endif /* _ACPI_H_ */

/* EOF */
