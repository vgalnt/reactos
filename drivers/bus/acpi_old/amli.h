/*
 * PROJECT:     ACPI driver for NT 5.x
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     ACPI Machine Language Interpreter (AMLI) header
 * COPYRIGHT:   Copyright 2019, 2023 Vadim Galyant <vgal@rambler.ru>
 */

/* STRUCTURES ***************************************************************/

typedef struct _AMLI_LIST
{
    struct _AMLI_LIST* Prev;
    struct _AMLI_LIST* Next;
} AMLI_LIST, *PAMLI_LIST;

typedef struct _AMLI_OBJECT_DATA
{
    USHORT Flags;
    USHORT DataType;
    union
    {
        ULONG RefCount;
        struct _AMLI_OBJECT_DATA* DataBase;
    };
    union
    {
        PVOID DataValue;
        struct _AMLI_NAME_SPACE_OBJECT* Alias;
        struct _AMLI_OBJECT_DATA* DataAlias;
        PVOID Owner;
    };
    ULONG DataLen;
    PVOID DataBuff;
} AMLI_OBJECT_DATA, *PAMLI_OBJECT_DATA;

typedef struct _AMLI_NAME_SPACE_OBJECT
{
    AMLI_LIST List;
    struct _AMLI_NAME_SPACE_OBJECT* Parent;
    struct _AMLI_NAME_SPACE_OBJECT* FirstChild;
    ULONG NameSeg;
    PVOID Owner;
    struct _AMLI_NAME_SPACE_OBJECT* OwnedNext;
    AMLI_OBJECT_DATA ObjData;
    PVOID Context;
    ULONG RefCount;
} AMLI_NAME_SPACE_OBJECT, *PAMLI_NAME_SPACE_OBJECT;

typedef struct _AMLI_OBJECT_OWNER
{
    AMLI_LIST List;
    ULONG Signature;
    PAMLI_NAME_SPACE_OBJECT ObjList;
} AMLI_OBJECT_OWNER, *PAMLI_OBJECT_OWNER;

struct _AMLI_CONTEXT;
typedef NTSTATUS (__cdecl* PAMLI_FN_PARSE)(struct _AMLI_CONTEXT* AmliContext, PVOID Context, NTSTATUS InStatus);

typedef struct _AMLI_FRAME_HEADER
{
    ULONG Signature;
    ULONG Length;
    ULONG Flags;
    PAMLI_FN_PARSE ParseFunction;
} AMLI_FRAME_HEADER, *PAMLI_FRAME_HEADER;

typedef struct _AMLI_CALL
{
    AMLI_FRAME_HEADER FrameHdr;
    struct _AMLI_CALL* CallPrev;
    PAMLI_OBJECT_OWNER OwnerPrev;
    PAMLI_NAME_SPACE_OBJECT NsMethod;
    ULONG ArgIndex;
    ULONG NumberOfArgs;
    PAMLI_OBJECT_DATA DataArgs;
    AMLI_OBJECT_DATA Locals[8];
    PAMLI_OBJECT_DATA DataResult;
} AMLI_CALL, *PAMLI_CALL;

typedef void (__cdecl* PAMLI_FN_ASYNC_CALLBACK)(PAMLI_NAME_SPACE_OBJECT Object, NTSTATUS InStatus, PAMLI_OBJECT_DATA Data, PVOID Context);

typedef struct _AMLI_NESTED_CONTEXT
{
    AMLI_FRAME_HEADER FrameHeader;
    PAMLI_NAME_SPACE_OBJECT Object;
    PAMLI_NAME_SPACE_OBJECT Scope;
    AMLI_OBJECT_DATA Result;
    PAMLI_FN_ASYNC_CALLBACK AsyncCallBack;
    PAMLI_OBJECT_DATA DataCallBack;
    PVOID Context;
    ULONG PrevCtxt;
    struct _AMLI_NESTED_CONTEXT* Prev;
} AMLI_NESTED_CONTEXT, *PAMLI_NESTED_CONTEXT;

typedef struct _AMLI_HEAP_HEADER
{
    ULONG Signature;
    ULONG Length;
    struct _AMLI_HEAP* Heap;
    AMLI_LIST List;
} AMLI_HEAP_HEADER, *PAMLI_HEAP_HEADER;

typedef struct _AMLI_HEAP
{
    ULONG Signature;
    PVOID HeapEnd;
    struct _AMLI_HEAP* HeapHead;
    struct _AMLI_HEAP* HeapNext;
    PVOID HeapTop;
    PAMLI_LIST ListFreeHeap;
    AMLI_HEAP_HEADER Heap;
} AMLI_HEAP, *PAMLI_HEAP;

typedef struct _AMLI_CONTEXT_DATA
{
    union
    {
        struct
        {
            PVOID Data1;
            PVOID Data2;
            PVOID Data3;
            PVOID Data4;
        };
        struct
        {
            PVOID Callback;
            USHORT LockData;
            USHORT Depth;
            LIST_ENTRY Link;
        };
    };
} AMLI_CONTEXT_DATA, *PAMLI_CONTEXT_DATA;

typedef struct _AMLI_CONTEXT
{
    ULONG Signature;
    PUCHAR End;
    AMLI_LIST List;
    AMLI_LIST QueueList;
    PAMLI_LIST* QueueLists;
    PAMLI_LIST ResourcesList;
    ULONG Flags;
    PAMLI_NAME_SPACE_OBJECT NsObject;
    PAMLI_NAME_SPACE_OBJECT Scope;
    PAMLI_OBJECT_OWNER Owner;
    PAMLI_CALL Call;
    PAMLI_NESTED_CONTEXT NestedContext;
    ULONG SyncLevel;
    PUCHAR Op;
    AMLI_OBJECT_DATA Result;
    PVOID AsyncCallBack;
    PAMLI_OBJECT_DATA DataCallBack;
    PVOID CallBackContext;
    KTIMER Timer;
    KDPC Dpc;
    PAMLI_HEAP HeapCurrent;
    AMLI_CONTEXT_DATA ContextData;
    AMLI_HEAP LocalHeap;
} AMLI_CONTEXT, *PAMLI_CONTEXT;

typedef struct _AMLI_TERM_CONTEXT *PAMLI_TERM_CONTEXT;
typedef NTSTATUS (__cdecl* PAMLI_TERM_HANDLER)(PAMLI_CONTEXT AmliContext, PAMLI_TERM_CONTEXT TermCtx);
typedef NTSTATUS (__cdecl* PAMLI_TERM_CALLBACK_1)(ULONG, ULONG, ULONG, PVOID, PVOID);

typedef struct _AMLI_TERM
{
    PCHAR Name;
    ULONG Opcode;
    PCHAR TypesOfArgs;
    ULONG Flags1;
    ULONG Flags2;
    PVOID CallBack;
    PVOID Context;
    PAMLI_TERM_HANDLER Handler;
} AMLI_TERM, *PAMLI_TERM;

typedef struct _AMLI_TERM_EX
{
    ULONG Opcode;
    PAMLI_TERM AmliTerm;
} AMLI_TERM_EX, *PAMLI_TERM_EX;

typedef struct _AMLI_TERM_CONTEXT
{
    AMLI_FRAME_HEADER FrameHeader;
    PUCHAR Op;
    PUCHAR OpEnd;
    PUCHAR ScopeEnd;
    PAMLI_TERM AmliTerm;
    PAMLI_NAME_SPACE_OBJECT NsObject;
    ULONG ArgIndex;
    ULONG NumberOfArgs;
    PAMLI_OBJECT_DATA DataArgs;
    PAMLI_OBJECT_DATA DataResult;
} AMLI_TERM_CONTEXT, *PAMLI_TERM_CONTEXT;

typedef NTSTATUS (__cdecl* PAMLI_FN_HANDLER)(ULONG, PVOID);
typedef NTSTATUS (__cdecl* PAMLI_FN_HANDLER2)(ULONG, ULONG, PVOID);

typedef struct _AMLI_EVHANDLE
{
    PVOID Handler;
    PVOID Context;
} AMLI_EVHANDLE, *PAMLI_EVHANDLE;

typedef struct _AMLI_MUTEX_OBJECT
{
    ULONG SyncLevel;
    ULONG OwnedCounter;
    PVOID Owner;
    PAMLI_LIST ListWaiters;
} AMLI_MUTEX_OBJECT, *PAMLI_MUTEX_OBJECT;

C_ASSERT(sizeof(AMLI_MUTEX_OBJECT) == 0x10);

typedef struct _AMLI_METHOD_OBJECT
{
    AMLI_MUTEX_OBJECT Mutex;
    UCHAR MethodFlags;
    UCHAR CodeBuff[1];
    UCHAR Pad[2];
} AMLI_METHOD_OBJECT, *PAMLI_METHOD_OBJECT;

typedef struct _AMLI_MUTEX
{
    KSPIN_LOCK SpinLock;
    KIRQL OldIrql;
    UCHAR Pad[3];
} AMLI_MUTEX, *PAMLI_MUTEX;

typedef VOID (__cdecl* PAMLI_FN_CALLBACK1)(PVOID Context);
typedef VOID (__cdecl* PAMLI_FN_CALLBACK2)(PAMLI_NAME_SPACE_OBJECT NsObject, NTSTATUS InStatus, ULONG Param3, PVOID Context);

typedef struct _AMLI_CONTEXT_QUEUE
{
    ULONG Flags;
    PKTHREAD Thread;
    PAMLI_CONTEXT CurrentContext;
    PAMLI_LIST List;
    ULONG TimeSliceLength;
    ULONG TimeSliceInterval;
    PAMLI_FN_CALLBACK1 PauseCallback;
    PVOID CallbackContext;
    AMLI_MUTEX Mutex;
    KTIMER Timer;
    KDPC DpcStartTimeSlice;
    KDPC DpcExpireTimeSlice;
    WORK_QUEUE_ITEM WorkItem;
} AMLI_CONTEXT_QUEUE, *PAMLI_CONTEXT_QUEUE;

C_ASSERT(sizeof(AMLI_CONTEXT_QUEUE) == 0xA0);

typedef struct _AMLI_SCOPE
{
    AMLI_FRAME_HEADER FrameHeader;
    PUCHAR OpEnd;
    PUCHAR OpcodeRet;
    PAMLI_NAME_SPACE_OBJECT OldScope;
    PAMLI_OBJECT_OWNER OldOwner;
    PAMLI_HEAP HeapCurrent;
    PAMLI_OBJECT_DATA DataResult;
} AMLI_SCOPE, *PAMLI_SCOPE;

typedef struct _AMLI_ASYNC_CONTEXT
{
    NTSTATUS Status;
    PAMLI_CONTEXT AmliContext;
    KEVENT Event;
} AMLI_ASYNC_CONTEXT, *PAMLI_ASYNC_CONTEXT;

typedef struct _AMLI_RESTART_CONTEXT
{
    PAMLI_CONTEXT AmliContext;
    WORK_QUEUE_ITEM WorkQueueItem;
} AMLI_RESTART_CONTEXT, *PAMLI_RESTART_CONTEXT;

typedef struct _AMLI_RESOURCE
{
    ULONG ResType;
    PAMLI_CONTEXT ContextOwner;
    PVOID ResObject;
    AMLI_LIST List;
} AMLI_RESOURCE, *PAMLI_RESOURCE;

typedef struct _AMLI_OP_REGION_OBJECT
{
    ULONG Offset;
    ULONG Len;
    UCHAR RegionSpace;
    UCHAR Reserved[3];
    LONG RegionBusy;
    ULONG ListLock;
    PAMLI_LIST ListWaiters;
} AMLI_OP_REGION_OBJECT, *PAMLI_OP_REGION_OBJECT;

typedef struct _AMLI_FIELD_DESCRIPTOR
{
    ULONG ByteOffset;
    ULONG StartBitPos;
    ULONG NumBits;
    ULONG FieldFlags;
} AMLI_FIELD_DESCRIPTOR, *PAMLI_FIELD_DESCRIPTOR;

typedef struct _AMLI_FIELD_UNIT_OBJECT
{
    AMLI_FIELD_DESCRIPTOR FieldDesc;
    PAMLI_NAME_SPACE_OBJECT NsFieldParent;
} AMLI_FIELD_UNIT_OBJECT, *PAMLI_FIELD_UNIT_OBJECT;

typedef struct _AMLI_RS_ACCESS_HANDLER
{
    struct _AMLI_RS_ACCESS_HANDLER* Next;
    ULONG RegionSpace;
    PVOID CookAccessHandler;
    PVOID CookAccessParam;
    PVOID RawAccessHandler;
    PVOID RawAccessParam;
} AMLI_RS_ACCESS_HANDLER, *PAMLI_RS_ACCESS_HANDLER;

typedef struct _AMLI_REGION_HANDLER
{
    PVOID CallBack;
    PVOID CallBackContext;
    ULONG EventType;
    ULONG EventData;
} AMLI_REGION_HANDLER, *PAMLI_REGION_HANDLER;

typedef NTSTATUS (__cdecl* PINTERNAL_OP_REGION_HANDLER)(ULONG AccType, PAMLI_NAME_SPACE_OBJECT BaseObj, ULONG Offset, ULONG Length, PVOID Buffer, PAMLI_REGION_HANDLER Handler, PVOID Callback, PVOID Context);

typedef struct _AMLI_OBJECT_TYPE_NAME
{
    ULONG Type;
    PCHAR Name;
} AMLI_OBJECT_TYPE_NAME, *PAMLI_OBJECT_TYPE_NAME;

typedef struct _AMLI_PACKAGE_OBJECT
{
    ULONG Elements;
    AMLI_OBJECT_DATA Data[1];
} AMLI_PACKAGE_OBJECT, *PAMLI_PACKAGE_OBJECT;

typedef struct _AMLI_PACKAGE_CONTEXT
{
    AMLI_FRAME_HEADER FrameHeader;
    PAMLI_PACKAGE_OBJECT PackageObject;
    ULONG ElementCount;
    PUCHAR OpEnd;
} AMLI_PACKAGE_CONTEXT, *PAMLI_PACKAGE_CONTEXT;

typedef struct _AMLI_AFU_CONTEXT // Access Field Unit
{
    AMLI_FRAME_HEADER FrameHeader;
    PAMLI_OBJECT_DATA DataObj;
    PAMLI_OBJECT_DATA DataResult;
} AMLI_AFU_CONTEXT, *PAMLI_AFU_CONTEXT;

typedef struct _AMLI_BUFF_FIELD_OBJECT
{
    AMLI_FIELD_DESCRIPTOR FieldDesc;
    PUCHAR DataBuff;
    ULONG BuffLen;
} AMLI_BUFF_FIELD_OBJECT, *PAMLI_BUFF_FIELD_OBJECT;

typedef struct _AMLI_INDEX_FIELD_OBJECT
{
    PAMLI_NAME_SPACE_OBJECT IndexObj;
    PAMLI_NAME_SPACE_OBJECT DataObj;
} AMLI_INDEX_FIELD_OBJECT, *PAMLI_INDEX_FIELD_OBJECT;

typedef struct _AMLI_ACCESS_FIELD_OBJECT
{
    AMLI_FRAME_HEADER FrameHeader;
    PAMLI_OBJECT_DATA DataObj;
    PUCHAR BufferStart;
    PUCHAR BufferEnd;
    ULONG AccSize;
    ULONG AccCount;
    ULONG Mask;
    ULONG BitPos1;
    ULONG BitPos2;
    ULONG CurrentNum;
    ULONG Data;
    AMLI_FIELD_DESCRIPTOR FieldDesc;
} AMLI_ACCESS_FIELD_OBJECT, *PAMLI_ACCESS_FIELD_OBJECT;

typedef struct _AML_ACQUIRE
{
    AMLI_FRAME_HEADER FrameHeader;
    PAMLI_MUTEX_OBJECT AmliMutex;
    USHORT Timeout;
    USHORT Pad;
    PAMLI_OBJECT_DATA DataResult;
} AML_ACQUIRE, *PAML_ACQUIRE;

typedef struct _ACPI_GET_CONTEXT
{
    ULONG Flags;
    ULONG NameSeg;
    LIST_ENTRY List;
    struct _DEVICE_EXTENSION* DeviceExtension;
    PAMLI_NAME_SPACE_OBJECT NsObject;
    PVOID CallBack;
    PVOID CallBackContext;
    PVOID* OutDataBuff;
    ULONG* OutDataLen;
    NTSTATUS Status;
    AMLI_OBJECT_DATA DataResult;
} ACPI_GET_CONTEXT, *PACPI_GET_CONTEXT;

typedef struct _AMLI_PROCESSOR_OBJECT
{
    ULONG PBlk;
    ULONG PBlkLen;
    CHAR ApicID;
    UCHAR Pad[3];
} AMLI_PROCESSOR_OBJECT, *PAMLI_PROCESSOR_OBJECT;

typedef struct _AMLI_POWER_RES_OBJECT
{
    UCHAR SystemLevel;
    UCHAR ResOrder;
} AMLI_POWER_RES_OBJECT, *PAMLI_POWER_RES_OBJECT;

typedef struct _AMLI_WRITE_FIELD_LOOP
{
    AMLI_FRAME_HEADER FrameHeader;
    PAMLI_OBJECT_DATA DataObj;
    PAMLI_FIELD_DESCRIPTOR FieldDesc;
    PVOID Buffer;
    ULONG Length;
    ULONG ByteCount;
} AMLI_WRITE_FIELD_LOOP, *PAMLI_WRITE_FIELD_LOOP;

typedef struct _AMLI_POST_CONTEXT
{
    AMLI_FRAME_HEADER FrameHeader;
    PVOID Data1;
    PVOID Data2;
    PAMLI_OBJECT_DATA DataResult;
} AMLI_POST_CONTEXT, *PAMLI_POST_CONTEXT;

typedef struct _ACPI_PCI_CONFIG_CONTEXT
{
    ULONG Type;
    PAMLI_NAME_SPACE_OBJECT NsObject;
    ULONG Offset;
    ULONG Length;
    PVOID Buffer;
    PVOID Handler;
    PVOID Callback;
    PVOID Context;
    PAMLI_NAME_SPACE_OBJECT ParentNsObject;
    ULONG Unknown1;
    ULONG Flags;
    LONG RefCount;
    PCI_SLOT_NUMBER SlotNumber;
    UCHAR BusNumber;
} ACPI_PCI_CONFIG_CONTEXT, *PACPI_PCI_CONFIG_CONTEXT;

typedef struct _ACPI_PCI_CONFIG_INT_CONTEXT
{
    ACPI_PCI_CONFIG_CONTEXT PciConfig;
    AMLI_NAME_SPACE_OBJECT NsObject;
} ACPI_PCI_CONFIG_INT_CONTEXT, *PACPI_PCI_CONFIG_INT_CONTEXT;

typedef struct _GET_OP_REGION_SCOPE
{
    PAMLI_NAME_SPACE_OBJECT NsObject;
    PAMLI_NAME_SPACE_OBJECT ParentNsObject;
    ULONG Flags;
    BOOLEAN IsPciDeviceValue;
    UCHAR Pad[3];
    LONG RefCount;
    PVOID CallBack;
    PVOID CallBackContext;
    PVOID Context;
} GET_OP_REGION_SCOPE, *PGET_OP_REGION_SCOPE;

typedef struct _IS_PCI_DEVICE_CONTEXT
{
    PAMLI_NAME_SPACE_OBJECT NsObject;
    ULONG Flags;
    PVOID UniqueId;
    PVOID HardwareId;
    PVOID CompatibleId;
    BOOLEAN IsPciDeviceValue;
    UCHAR Pad[3];
    LONG RefCount;
    PVOID CallBack;
    PVOID CallBackContext;
    BOOLEAN* OutIsPciDevice;
} IS_PCI_DEVICE_CONTEXT, *PIS_PCI_DEVICE_CONTEXT;

typedef struct _ACPI_PCI_ADDRESS_DATA
{
    PAMLI_NAME_SPACE_OBJECT NsObject;
    UCHAR* OutBusNumber;
    PCI_SLOT_NUMBER* OutSlotNumber;
    UCHAR ParentBusNumber;
    UCHAR Pad[3];
    PCI_SLOT_NUMBER ParentSlotNumber;
    ULONG Flags;
    ULONG PciAddress;
    ULONG BaseBusNumber;
    LONG RefCount;
    PVOID CallBack;
    PVOID CallBackContext;
} ACPI_PCI_ADDRESS_DATA, *PACPI_PCI_ADDRESS_DATA;

typedef struct _SYNC_EVAL_CONTEXT
{
    NTSTATUS RetStatus;
    PAMLI_CONTEXT AmliContext;
    KEVENT Event;
} SYNC_EVAL_CONTEXT, *PSYNC_EVAL_CONTEXT;

typedef struct _DISABLE_LINK_NODES_CONTEXT
{
    ULONG Type;
    PAMLI_NAME_SPACE_OBJECT NsObject;
    PVOID DataBuff;
    ULONG Unknown1;
    PAMLI_NAME_SPACE_OBJECT ChildNsObject;
    ULONG Unknown2;
    LONG RefCount;
    PVOID Callback;
    PVOID Context;
} DISABLE_LINK_NODES_CONTEXT, *PDISABLE_LINK_NODES_CONTEXT;

typedef struct _AMLI_WRITE_COOK_ACCESS
{
    AMLI_FRAME_HEADER FrameHeader;
    PAMLI_NAME_SPACE_OBJECT BaseObj;
    PAMLI_RS_ACCESS_HANDLER RsAccess;
    PVOID Addr;
    ULONG Size;
    ULONG Value;
    ULONG DataMask;
    ULONG Data;
    BOOLEAN IsReadBeforeWrite;
    UCHAR Pad1[3];
} AMLI_WRITE_COOK_ACCESS, *PAMLI_WRITE_COOK_ACCESS;

typedef struct _AMLI_PASSIVE_HOOK
{
    PAMLI_CONTEXT AmliContext;
    PVOID BaseAddress;
    SIZE_T NumberOfBytes;
    PVOID* OutMappedAddr;
    WORK_QUEUE_ITEM WorkQueueItem;
} AMLI_PASSIVE_HOOK, *PAMLI_PASSIVE_HOOK;

typedef struct _AMLI_PRESERVE_WRITE_CONTEXT
{
    AMLI_FRAME_HEADER FrameHeader;
    PAMLI_OBJECT_DATA DataObj;
    ULONG Data;
    ULONG Mask;
    ULONG PrevData;
} AMLI_PRESERVE_WRITE_CONTEXT, *PAMLI_PRESERVE_WRITE_CONTEXT;

typedef struct _AMLI_SLEEP_QUEUE_CONTEXT
{
    AMLI_FRAME_HEADER FrameHeader;
    LIST_ENTRY Link;
    ULONGLONG InterruptTime;
    PAMLI_CONTEXT AmliContext;
    ULONG Unknown;
} AMLI_SLEEP_QUEUE_CONTEXT, *PAMLI_SLEEP_QUEUE_CONTEXT;

typedef struct _AMLI_OBJECT_SYMBOL
{
    struct _AMLI_OBJECT_SYMBOL* Prev;
    struct _AMLI_OBJECT_SYMBOL* Next;
    PCHAR Op;
    PAMLI_NAME_SPACE_OBJECT NsObject;
} AMLI_OBJECT_SYMBOL, *PAMLI_OBJECT_SYMBOL;

typedef struct _AMLI_BREAK_POINT
{
    ULONG Flags;
    PCHAR BrkPt;
} AMLI_BREAK_POINT, *PAMLI_BREAK_POINT;

typedef struct _AMLI_EVENT_LOG
{
    ULONG Event;
    ULONGLONG Time;
    ULONG Data1;
    ULONG Data2;
    ULONG Data3;
    ULONG Data4;
    ULONG Data5;
    ULONG Data6;
    ULONG Data7;
} AMLI_EVENT_LOG, *PAMLI_EVENT_LOG;

typedef struct _AMLI_EVENT_HANDLE
{
    LONG (__cdecl* Handler)();
    ULONG Param;
} AMLI_EVENT_HANDLE, *PAMLI_EVENT_HANDLE;

typedef struct _AMLI_DEBUGGER
{
    ULONG Flags;
    LONG PrintLevel;
    ULONG DumpDataAddr;
    PCHAR UnAsm;
    PCHAR UnAsmEnd;
    PCHAR BlkBegin;
    PCHAR BlkEnd;
    PAMLI_OBJECT_SYMBOL SymbolList;
    AMLI_BREAK_POINT BrkPts[10];
    ULONG LogSize;
    ULONG LogIndex;
    PAMLI_EVENT_LOG EventLog;
    AMLI_EVENT_HANDLE ConMessage;
    AMLI_EVENT_HANDLE ConPrompt;
    LONG LastError;
    CHAR LastErrorBuff[256];
} AMLI_DEBUGGER, *PAMLI_DEBUGGER;

typedef struct _AMLI_DBG_CMD_ARG
{
    PCHAR Name;
    ULONG Type;
    ULONG Context1;
    PVOID CmdArg;
    ULONG Context2;
    PVOID Handler;
} AMLI_DBG_CMD_ARG, *PAMLI_DBG_CMD_ARG;

typedef struct _AMLI_DBG_CMD
{
    PCHAR Cmd;
    ULONG Context;
    PAMLI_DBG_CMD_ARG Args;
    PVOID Handler;
} AMLI_DBG_CMD, *PAMLI_DBG_CMD;

/* FUNCTIONS ****************************************************************/

#if 1
NTSTATUS __cdecl Acquire(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Alias(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl BankField(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Break(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl BreakPoint(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Buffer(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Concat(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl CondRefOf(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl CreateBitField(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl CreateByteField(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl CreateDWordField(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl CreateField(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl CreateWordField(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl DerefOf(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Device(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Divide(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Event(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl ExprOp1(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl ExprOp2(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Fatal(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Field(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl IfElse(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl IncDec(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Index(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl IndexField(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl LNot(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Load(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl LogOp2(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Match(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Method(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Mutex(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Name(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Notify(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl ObjTypeSizeOf(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl OpRegion(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl OSInterface(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Package(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl PowerRes(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Processor(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl RefOf(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl ReleaseResetSignalUnload(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Return(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Scope(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl SleepStall(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Store(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl ThermalZone(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl Wait(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
NTSTATUS __cdecl While(_In_ PAMLI_CONTEXT AmliContext, _In_ PAMLI_TERM_CONTEXT TermContext);
#endif

NTSTATUS
NTAPI
ACPIInitializeAMLI(
    VOID
);

NTSTATUS
__cdecl 
AMLILoadDDB(
    _In_ PDSDT Dsdt,
    _Out_ HANDLE* OutHandle
);

NTSTATUS
__cdecl
AMLIGetNameSpaceObject(
    _In_ PCHAR ObjPath,
    _In_ PAMLI_NAME_SPACE_OBJECT ScopeObject,
    _Out_ PAMLI_NAME_SPACE_OBJECT* OutNsObject,
    _In_ ULONG Flags
);

PAMLI_NAME_SPACE_OBJECT
NTAPI
ACPIAmliGetNamedChild(
    _In_ PAMLI_NAME_SPACE_OBJECT AcpiObject,
    _In_ ULONG NameSeg
);

NTSTATUS
__cdecl
AMLIAsyncEvalObject(
    _In_ PAMLI_NAME_SPACE_OBJECT AcpiObject,
    _In_ PAMLI_OBJECT_DATA DataResult,
    _In_ ULONG ArgsCount,
    _In_ PAMLI_OBJECT_DATA DataArgs,
    _In_ PAMLI_FN_ASYNC_CALLBACK InAsyncCallBack,
    _In_ PVOID CallBackContext
);

NTSTATUS
__cdecl
PushTerm(
    _In_ PAMLI_CONTEXT AmliContext,
    _In_ PUCHAR OpTerm,
    _In_ PUCHAR ScopeEnd,
    _In_ PAMLI_TERM AmliTerm,
    _In_ PAMLI_OBJECT_DATA DataResult
);

NTSTATUS
__cdecl
ParseOpcode(
    _In_ PAMLI_CONTEXT AmliContext,
    _In_ PUCHAR ScopeEnd,
    _In_ PAMLI_OBJECT_DATA DataResult
);

NTSTATUS
__cdecl
CreateNameSpaceObject(
    _In_ PAMLI_HEAP Heap,
    _In_ PCHAR Name,
    _In_ PAMLI_NAME_SPACE_OBJECT NsScope,
    _In_ PAMLI_OBJECT_OWNER Owner,
    _Out_ PAMLI_NAME_SPACE_OBJECT* OutObject,
    _In_ ULONG Flags
);

PVOID
__cdecl
HeapAlloc(
    _In_ PAMLI_HEAP InHeap,
    _In_ ULONG NameSeg,
    _In_ ULONG Length
);

NTSTATUS
__cdecl
GetNameSpaceObject(
    _In_ PCHAR ObjPath,
    _In_ PAMLI_NAME_SPACE_OBJECT ScopeObject,
    _In_ PAMLI_NAME_SPACE_OBJECT* OutObject,
    _In_ ULONG Flags
);

NTSTATUS
__cdecl
ParseFieldList(
    _In_ PAMLI_CONTEXT AmliContext,
    _In_ PUCHAR OpEnd,
    _In_ PAMLI_NAME_SPACE_OBJECT NsParentObject,
    _In_ ULONG FieldFlags,
    _In_ ULONG RegionLen
);

NTSTATUS
__cdecl
PushScope(
    _In_ PAMLI_CONTEXT AmliContext,
    _In_ PUCHAR OpcodeBegin,
    _In_ PUCHAR OpEnd,
    _In_ PUCHAR OpcodeRet,
    _In_ PAMLI_NAME_SPACE_OBJECT NsScope,
    _In_ PAMLI_OBJECT_OWNER Owner,
    _In_ PAMLI_HEAP Heap,
    _In_ PAMLI_OBJECT_DATA DataResult
);

NTSTATUS
__cdecl
PushFrame(
    _In_ PAMLI_CONTEXT AmliContext,
    _In_ ULONG Signature,
    _In_ ULONG Length,
    _In_ PVOID ParseFunction,
    _Out_ PVOID* OutFrame
);

VOID
__cdecl
PopFrame(
    _In_ PAMLI_CONTEXT AmliContext
);

NTSTATUS
__cdecl
ParseIntObj(
    _Inout_ PUCHAR* OutOp,
    _In_ PAMLI_OBJECT_DATA DataResult,
    _In_ BOOLEAN ErrOk
);

NTSTATUS
__cdecl
ParseString(
    _Inout_ PUCHAR* OutOp,
    _In_ PAMLI_OBJECT_DATA DataResult,
    _In_ BOOLEAN ErrOk
);

NTSTATUS
__cdecl
ParseObjName(
    _Inout_ PUCHAR* OutOp,
    _In_ PAMLI_OBJECT_DATA Data,
    _In_ BOOLEAN ErrOk
);

NTSTATUS
__cdecl
PushAccFieldObj(
    _In_ PAMLI_CONTEXT AmliContext,
    _In_ PVOID AccCallBack,
    _In_ PAMLI_OBJECT_DATA DataObj,
    _In_ PAMLI_FIELD_DESCRIPTOR FieldDesc,
    _In_ PUCHAR Buffer,
    _In_ ULONG ByteCount
);

NTSTATUS
__cdecl
ReadFieldObj(
    _In_ PAMLI_CONTEXT AmliContext,
    _In_ PAMLI_ACCESS_FIELD_OBJECT Afo,
    _In_ NTSTATUS InStatus
);

NTSTATUS
__cdecl
ParseAndGetNameSpaceObject(
    _Out_ PUCHAR* OutOp,
    _In_ PAMLI_NAME_SPACE_OBJECT ScopeObject,
    _Out_ PAMLI_NAME_SPACE_OBJECT* OutNsObject,
    _In_ BOOLEAN AbsentOk
);

VOID
__cdecl
FreeDataBuffs(
    _In_ PAMLI_OBJECT_DATA AmliData,
    _In_ LONG DataCount
);

ULONG
__cdecl
ParsePackageLen(
    _Inout_ PUCHAR* OutOp,
    _Out_ PUCHAR* OutOpEnd
);

NTSTATUS
__cdecl
ParseArg(
    _In_ PAMLI_CONTEXT AmliContext,
    _In_ CHAR ArgType,
    _In_ PAMLI_OBJECT_DATA DataArg
);

VOID
__cdecl
AMLIFreeDataBuffs(
    _In_ PAMLI_OBJECT_DATA Data,
    _In_ ULONG Count
);

NTSTATUS
__cdecl
InsertReadyQueue(
    _In_ PAMLI_CONTEXT AmliContext,
    _In_ BOOLEAN IsDelayExecute
);

NTSTATUS
__cdecl
WriteFieldObj(
    _In_ PAMLI_CONTEXT AmliContext,
    _In_ PAMLI_ACCESS_FIELD_OBJECT Afo,
    _In_ NTSTATUS InStatus
);

NTSTATUS
__cdecl
PushPost(
    _In_ PAMLI_CONTEXT AmliContext,
    _In_ PVOID PostCallBack,
    _In_ PVOID Data1,
    _In_ PVOID Data2,
    _In_ PAMLI_OBJECT_DATA DataResult
);

NTSTATUS
__cdecl
ReadObject(
    _In_ PAMLI_CONTEXT AmliContext,
    _In_ PAMLI_OBJECT_DATA DataObj,
    _In_ PAMLI_OBJECT_DATA DataResult
);

NTSTATUS
__cdecl
RestartContext(
    _In_ PAMLI_CONTEXT AmliContext,
    _In_ BOOLEAN IsDelayExecute
);

NTSTATUS
__cdecl
RunContext(
    _In_ PAMLI_CONTEXT AmliContext
);

NTSTATUS
NTAPI
IsPciDevice(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ PVOID CallBack,
    _In_ PVOID CallBackContext,
    _Out_ BOOLEAN* OutIsPciDevice
);

NTSTATUS
NTAPI
GetPciAddress(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ PCHAR CompletionRoutine,
    _In_ PVOID Context,
    _Out_ UCHAR* OutBusNumber,
    _Out_ PCI_SLOT_NUMBER* OutSlotNumber
);

NTSTATUS
__cdecl
AMLIEvalPackageElement(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ ULONG Index,
    _In_ PAMLI_OBJECT_DATA DataResult
);

NTSTATUS
__cdecl
AMLIEvalNameSpaceObject(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _Out_ AMLI_OBJECT_DATA* DataResult,
    _In_ ULONG ArgsCount,
    _In_ PAMLI_OBJECT_DATA DataArgs
);

NTSTATUS
__cdecl
AsyncEvalObject(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ PVOID DataResult,
    _In_ ULONG ArgsCount,
    _In_ PAMLI_OBJECT_DATA DataArgs,
    _In_ PAMLI_FN_ASYNC_CALLBACK InAsyncCallBack,
    _In_ PVOID CallBackContext,
    _In_ BOOLEAN IsAsync
);

VOID
__cdecl
EvalMethodComplete(
    _In_ PAMLI_CONTEXT AmliContext,
    _In_ NTSTATUS InStatus,
    _In_ PVOID Context
);

VOID
__cdecl
AmlisuppCompletePassive(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ NTSTATUS InStatus,
    _In_ ULONG Param3,
    _In_ PVOID Context
);

NTSTATUS
__cdecl
PciConfigSpaceHandlerWorker(
    _In_ PAMLI_NAME_SPACE_OBJECT InNsObject,
    _In_ NTSTATUS InStatus,
    _In_ ULONG Param3,
    _In_ PVOID Context
);

NTSTATUS
__cdecl
AMLIEvalPkgDataElement(
    _In_ PAMLI_OBJECT_DATA Data,
    _In_ ULONG Index,
    _In_ PAMLI_OBJECT_DATA DataResult
);

NTSTATUS
__cdecl
InitMutex(
    _In_ PAMLI_HEAP Heap,
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ ULONG Level
);

NTSTATUS
__cdecl
ParseAcquire(
    _In_ PAMLI_CONTEXT AmliContext,
    _In_ PAML_ACQUIRE AmliAcquire,
    _In_ NTSTATUS InStatus
);

NTSTATUS
__cdecl
ReleaseASLMutex(
    _In_ PAMLI_CONTEXT AmliContext,
    _In_ PAMLI_MUTEX_OBJECT AmliMutex
);

/* EOF */
