#ifndef _MSPORTS_
#define _MSPORTS_

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_HANDLE(HCOMDB);
typedef HCOMDB *PHCOMDB;
#define HCOMDB_INVALID_HANDLE_VALUE ((HCOMDB)INVALID_HANDLE_VALUE)

/* Limits for ComDBResizeDatabase NewSize */
#define COMDB_MIN_PORTS_ARBITRATED 256
#define COMDB_MAX_PORTS_ARBITRATED 4096

/* ReportType flags for ComDBGetCurrentPortUsage */
#define CDB_REPORT_BITS  0x0
#define CDB_REPORT_BYTES 0x1

LONG
WINAPI
ComDBClaimNextFreePort(
    _In_ HCOMDB hComDB,
    _Out_ DWORD* OutComNumber
);

LONG
WINAPI
ComDBClaimPort(
    _In_ HCOMDB hComDB,
    _In_ DWORD ComNumber,
    _In_ BOOL IsForceClaim,
    _Out_ BOOL* OutIsForced
);

LONG
WINAPI
ComDBClose(
    _In_ HCOMDB hComDB
);

LONG
WINAPI
ComDBGetCurrentPortUsage(
    _In_ HCOMDB hComDB,
    _Out_ BYTE* OutBuffer,
    _In_ DWORD BufferSize,
    _In_ DWORD ReportType,
    _Out_ DWORD* OutMaxPortsReported
);

LONG
WINAPI
ComDBOpen(
    _Out_ HCOMDB* phComDB
);

LONG
WINAPI
ComDBReleasePort(
    _In_ HCOMDB hComDB,
    _In_ DWORD ComNumber
);

LONG
WINAPI
ComDBResizeDatabase(
    _In_ HCOMDB hComDB,
    _In_ DWORD NewSize
);

#ifdef __cplusplus
}
#endif

#endif /* _MSPORTS_ */
