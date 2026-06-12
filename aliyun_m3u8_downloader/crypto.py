"""Cryptographic helpers.

Ports ``pkg/tool/crypto.go`` and ``pkg/tool/aliyun_aes.go``:

* standard AES-128-CBC (HLS standard encryption)
* AES-128-ECB (used inside the Aliyun TS payload decryption)
* the RSA + AES key-exchange used to recover the Aliyun VoD TS key
"""

from __future__ import annotations

import base64
import hashlib

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

# RSA public key embedded in the original client, used to encrypt the
# client random before requesting the play info.
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIcLeIt2wmIyXckgNhCGpMTAZyBGO+nk0/IdOrhIdfRR
gBLHdydsftMVPNHrRuPKQNZRslWE1vvgx80w9lCllIUCAwEAAQ==
-----END PUBLIC KEY-----"""

BLOCK_SIZE = 16


def _pkcs5_unpad(data: bytes) -> bytes:
    if not data:
        return data
    return data[: -data[-1]]


def aes128_cbc_decrypt(data: bytes, key: bytes, iv: bytes = b"") -> bytes:
    """Standard HLS AES-128-CBC decryption (with PKCS#5 unpadding)."""
    if not iv:
        iv = key
    cipher = AES.new(key, AES.MODE_CBC, iv[:BLOCK_SIZE])
    return _pkcs5_unpad(cipher.decrypt(data))


def aes128_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    """AES-128-ECB decryption without unpadding (Aliyun PES payloads).

    Only whole 16-byte blocks are decrypted; any trailing bytes are left
    untouched, matching the original implementation.
    """
    n = len(data) - len(data) % BLOCK_SIZE
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data[:n]) + data[n:]


def _aes_cbc_decrypt_b64(key: bytes, iv: bytes, text: str) -> str:
    """Base64-decode then AES-128-CBC decrypt to a string (key exchange step)."""
    try:
        raw = base64.b64decode(text)
    except Exception:
        return ""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return _pkcs5_unpad(cipher.decrypt(raw)).decode("utf-8", "ignore")


def _md5_hex(value: str) -> str:
    return hashlib.md5(value.encode()).hexdigest()


def decrypt_key(r1: str, server_rand: str, plaintext: str) -> str:
    """Recover the Aliyun VoD TS AES key (returned as a hex string).

    ``r1`` is the client random, ``server_rand`` / ``plaintext`` come from the
    play-info response.
    """
    temp_key = _md5_hex(r1)[8:24].encode()
    iv = temp_key
    rand_decrypted = _aes_cbc_decrypt_b64(temp_key, iv, server_rand)
    temp_key2 = _md5_hex(r1 + rand_decrypted)[8:24].encode()
    final_key = _aes_cbc_decrypt_b64(temp_key2, iv, plaintext)
    return base64.b64decode(final_key).hex()


def encrypt_rand(data: bytes) -> str:
    """RSA/PKCS1-v1.5 encrypt the client random, returned base64-encoded."""
    cipher = PKCS1_v1_5.new(RSA.import_key(PUBLIC_KEY))
    return base64.b64encode(cipher.encrypt(data)).decode()
