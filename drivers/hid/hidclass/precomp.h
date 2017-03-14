#ifndef _HIDCLASS_PCH_
#define _HIDCLASS_PCH_

#define _HIDPI_NO_FUNCTION_MACROS_
#include <ntddk.h>
#include <wdm.h>
#include <hidpddi.h>
#include <stdio.h>
#include <hidport.h>
#include <poclass.h>

#define HIDCLASS_TAG 'CdiH'
#define HIDCLASS_NULL_POINTER (PVOID)0xFFFFFFB0

#define HIDCLASS_STATE_NOT_INIT  1
#define HIDCLASS_STATE_STARTING  2
#define HIDCLASS_STATE_STARTED   3
#define HIDCLASS_STATE_FAILED    4
#define HIDCLASS_STATE_STOPPING  5
#define HIDCLASS_STATE_DISABLED  6
#define HIDCLASS_STATE_REMOVED   7
#define HIDCLASS_STATE_DELETED   8

#define HIDCLASS_MINIMUM_SHUTTLE_IRPS    2
#define HIDCLASS_MAX_REPORT_QUEUE_SIZE   32

/* Shuttle state */
#define HIDCLASS_SHUTTLE_START_READ      1
#define HIDCLASS_SHUTTLE_END_READ        2
#define HIDCLASS_SHUTTLE_DISABLED        3

typedef struct _HIDCLASS_FDO_EXTENSION *PHIDCLASS_FDO_EXTENSION;
typedef struct _HIDCLASS_PDO_DEVICE_EXTENSION *PHIDCLASS_PDO_DEVICE_EXTENSION;

/* Header for interrupt report */
typedef struct _HIDCLASS_INT_REPORT_HEADER {
    LIST_ENTRY ReportLink;
    ULONG InputLength;
} HIDCLASS_INT_REPORT_HEADER, *PHIDCLASS_INT_REPORT_HEADER;

typedef struct _HIDCLASS_SHUTTLE {
    LONG ShuttleState;
    PIRP ShuttleIrp;
    PVOID ShuttleBuffer;
    LONG CancellingShuttle;
    KEVENT ShuttleEvent;
    KEVENT ShuttleDoneEvent;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    KTIMER ShuttleTimer;
    KDPC ShuttleTimerDpc;
    LARGE_INTEGER TimerPeriod;
} HIDCLASS_SHUTTLE, *PHIDCLASS_SHUTTLE;

typedef struct _HIDCLASS_COLLECTION {
    ULONG CollectionNumber;
    ULONG CollectionIdx;
    ULONG NumPendingReads;
    LIST_ENTRY InterruptReportList;
    KSPIN_LOCK CollectSpinLock;
    KSPIN_LOCK CollectCloseSpinLock;
    HID_COLLECTION_INFORMATION HidCollectInfo;
    PVOID CollectionData;
    PVOID InputReport;
    ULONG CloseFlag;
    PVOID PollReport;
    ULONG PollReportLength;
    UNICODE_STRING SymbolicLinkName;
} HIDCLASS_COLLECTION, *PHIDCLASS_COLLECTION;

typedef struct {
    PDRIVER_OBJECT DriverObject;
    ULONG DeviceExtensionSize;
    BOOLEAN DevicesArePolled;
    UCHAR Reserved[3];
    PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
    PDRIVER_ADD_DEVICE AddDevice;
    PDRIVER_UNLOAD DriverUnload;
    LONG RefCount;
    LIST_ENTRY DriverExtLink;
} HIDCLASS_DRIVER_EXTENSION, *PHIDCLASS_DRIVER_EXTENSION;

typedef struct {

    //
    // hid device extension
    //
    HID_DEVICE_EXTENSION HidDeviceExtension;

    //
    // if it is a pdo
    //
    BOOLEAN IsFDO;

    //
    // driver extension
    //
    PHIDCLASS_DRIVER_EXTENSION DriverExtension;

    //
    // device description
    //
    HIDP_DEVICE_DESC DeviceDescription;

    //
    // hid attributes
    //
    HID_DEVICE_ATTRIBUTES Attributes;

} HIDCLASS_COMMON_DEVICE_EXTENSION, *PHIDCLASS_COMMON_DEVICE_EXTENSION;

typedef struct _HIDCLASS_FDO_EXTENSION {

    //
    // parts shared by fdo and pdo
    //
    HIDCLASS_COMMON_DEVICE_EXTENSION Common;

    //
    // device capabilities
    //
    DEVICE_CAPABILITIES Capabilities;

    //
    // hid descriptor
    //
    HID_DESCRIPTOR HidDescriptor;

    //
    // report descriptor
    //
    PUCHAR ReportDescriptor;

    //
    // device relations
    //
    PDEVICE_RELATIONS DeviceRelations;
    /* An array of pointers to _HIDCLASS_PDO_DEVICE_EXTENSION */
    PHIDCLASS_PDO_DEVICE_EXTENSION * ClientPdoExtensions;
    /* FDO PnP state */
    ULONG HidFdoState;
    /* Previous FDO PnP state */
    ULONG HidFdoPrevState;
    /* FDO flags */
    BOOLEAN NotAllocCollectResources;
    BOOLEAN IsNotifyPresence;
    BOOLEAN IsRelationsOn;
    BOOLEAN IsDeviceResourcesAlloceted;
    /* An array of HIDCLASS_COLLECTION structures */
    PHIDCLASS_COLLECTION HidCollections;
    /* Number of shuttles */
    ULONG ShuttleCount;
    /* An array of PHIDCLASS_SHUTTLE structures */
    PHIDCLASS_SHUTTLE Shuttles;
    /* Maximum length of reports */
    ULONG MaxReportSize;
    /* Self FDO device object */
    PDEVICE_OBJECT FDODeviceObject;
    LONG OutstandingRequests;
    /* SpinLocks */
    KSPIN_LOCK HidRelationSpinLock;
    KSPIN_LOCK HidRemoveDeviceSpinLock;
    /* Opens Counter */
    LONG OpenCount;

} HIDCLASS_FDO_EXTENSION, *PHIDCLASS_FDO_EXTENSION;

typedef struct _HIDCLASS_PDO_DEVICE_EXTENSION {

    //
    // parts shared by fdo and pdo
    //
    HIDCLASS_COMMON_DEVICE_EXTENSION Common;

    /* PDO device object */
    PDEVICE_OBJECT SelfDevice;
    /* PDO index */
    ULONG PdoIdx;

    //
    // device capabilities
    //
    DEVICE_CAPABILITIES Capabilities;

    //
    // collection index
    //
    ULONG CollectionNumber;

    //
    // device interface
    //
    UNICODE_STRING DeviceInterface;

    //
    // FDO device object
    //
    PDEVICE_OBJECT FDODeviceObject;

    //
    // fdo device extension
    //
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;

    /* PDO PnP state */
    ULONG HidPdoState;
    /* Previous PDO PnP state */
    ULONG HidPdoPrevState;
    /* PDO flags */
    BOOLEAN IsGenericHid;
    BOOLEAN IsSessionSecurity;
    UCHAR Reserved1[2];
    /* Opens Counter */
    LONG OpenCount;
    LONG OpensForRead;
    LONG OpensForWrite;
    LONG RestrictionsForRead;
    LONG RestrictionsForWrite;
    LONG RestrictionsForAnyOpen;

} HIDCLASS_PDO_DEVICE_EXTENSION, *PHIDCLASS_PDO_DEVICE_EXTENSION;

typedef struct _HIDCLASS_FILEOP_CONTEXT {

    //
    // device extension
    //
    PHIDCLASS_PDO_DEVICE_EXTENSION DeviceExtension;

    //
    // spin lock
    //
    KSPIN_LOCK Lock;

    //
    // read irp pending list
    //
    LIST_ENTRY ReadPendingIrpListHead;

    //
    // completed irp list
    //
    LIST_ENTRY IrpCompletedListHead;

    //
    // stop in progress indicator
    //
    BOOLEAN StopInProgress;
    BOOLEAN IsMyPrivilegeTrue;
    UCHAR Reserved1[2];

    //
    // read complete event
    //
    KEVENT IrpReadComplete;
    /* Read IRP pending list */
    LIST_ENTRY InterruptReadIrpList;
    /* Report list */
    LIST_ENTRY ReportList;
    LIST_ENTRY InterruptReportLink;
    ULONG MaxReportQueueSize;
    LONG PendingReports;
    LONG RetryReads;
    PFILE_OBJECT FileObject;
    USHORT FileAttributes;
    USHORT ShareAccess;
    ULONG SessionId;
    ULONG DesiredAccess;

} HIDCLASS_FILEOP_CONTEXT, *PHIDCLASS_FILEOP_CONTEXT;

typedef struct
{
    //
    // original request
    //
    PIRP OriginalIrp;

    //
    // file op
    //
    PHIDCLASS_FILEOP_CONTEXT FileOp;

    //
    // buffer for reading report
    //
    PVOID InputReportBuffer;

    //
    // buffer length
    //
    ULONG InputReportBufferLength;

    //
    // work item
    //
    PIO_WORKITEM CompletionWorkItem;

    /* for HACK: use instead Irp->Tail.Overlay.ListEntry (use usbport)
       link with pending IRPs list 
    */
    LIST_ENTRY ReadIrpLink;
} HIDCLASS_IRP_CONTEXT, *PHIDCLASS_IRP_CONTEXT;

/* hidclass.c */
PHIDCLASS_DRIVER_EXTENSION
NTAPI
RefDriverExt(
    IN PDRIVER_OBJECT DriverObject);

PHIDCLASS_DRIVER_EXTENSION
NTAPI
DerefDriverExt(
    IN PDRIVER_OBJECT DriverObject);

/* fdo.c */
PHIDCLASS_COLLECTION
NTAPI
GetHidclassCollection(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension,
    IN ULONG CollectionNumber);

NTSTATUS
HidClassFDO_PnP(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp);

NTSTATUS
HidClassFDO_DispatchRequest(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp);

NTSTATUS
HidClassFDO_DispatchRequestSynchronous(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp);

NTSTATUS
NTAPI
HidClassSubmitInterruptRead(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension,
    IN PHIDCLASS_SHUTTLE Shuttle,
    IN BOOLEAN * OutIsSending);

/* pdo.c */
NTSTATUS
HidClassCreatePDOs(
    IN PDEVICE_OBJECT DeviceObject,
    OUT PDEVICE_RELATIONS *OutDeviceRelations);

NTSTATUS
HidClassPDO_PnP(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp);

PHIDP_COLLECTION_DESC
HidClassPDO_GetCollectionDescription(
    PHIDP_DEVICE_DESC DeviceDescription,
    ULONG CollectionNumber);

PHIDP_REPORT_IDS
HidClassPDO_GetReportDescription(
    PHIDP_DEVICE_DESC DeviceDescription,
    ULONG CollectionNumber);

BOOLEAN
NTAPI
HidClassAllPdoInitialized(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension,
    IN BOOLEAN Type);

#endif /* _HIDCLASS_PCH_ */
