#pragma once

#define STATUS_ENCOUNTERED_WRITE_IN_PROGRESS 0xC0000433


#define NODE_TYPE_MBCB           0x02FB
#define NODE_TYPE_DEFERRED_WRITE 0x02FC
#define NODE_TYPE_BCB            0x02FD
#define NODE_TYPE_PRIVATE_MAP    0x02FE
#define NODE_TYPE_SHARED_MAP     0x02FF

/* SharedCacheMap->Flags */
#define SHARE_FL_PIN_ACCESS        0x00000004
#define SHARE_FL_TRUNCATE_SIZE     0x00000010
#define SHARE_FL_WRITE_QUEUED      0x00000020
#define SHARE_FL_SEQUENTIAL_ONLY   0x00000040
#define SHARE_FL_VACB_LOCKED       0x00000080
#define SHARE_FL_SECTION_INIT      0x00000100
#define SHARE_FL_MODIFIED_NO_WRITE 0x00000200
#define SHARE_FL_RANDOM_ACCESS     0x00001000
#define SHARE_FL_READ_AHEAD        0x00004000
#define SHARE_FL_WAITING_TEARDOWN  0x00010000

/* Counters */
extern ULONG CcLazyWritePages;
extern ULONG CcLazyWriteIos;
extern ULONG CcMapDataWait;
extern ULONG CcMapDataNoWait;
extern ULONG CcPinReadWait;
extern ULONG CcPinReadNoWait;
extern ULONG CcPinMappedDataCount;
extern ULONG CcDataPages;
extern ULONG CcDataFlushes;

/* cachesub.c */
//INIT_FUNCTION
VOID
NTAPI
CcPfInitializePrefetcher(
    VOID
);

/* copysup.c */

/* fssup.c */
//INIT_FUNCTION
BOOLEAN
NTAPI
CcInitializeCacheManager(
    VOID
);

VOID
NTAPI
CcWaitForUninitializeCacheMap(
    _In_ PFILE_OBJECT FileObject
);

VOID
NTAPI
CcZeroEndOfLastPage(
    _In_ PFILE_OBJECT FileObject
);

/* lazyrite.c */

/* logsup.c */

/* mdlsup.c */
VOID
NTAPI
CcMdlReadComplete2(
    IN PFILE_OBJECT FileObject,
    IN PMDL MemoryDescriptorList
);

VOID
NTAPI
CcMdlWriteComplete2(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PMDL MdlChain
);

/* pinsup.c */

/* vacbsup.c */


/* EOF */
