import base64
import hashlib

from Crypto.Cipher import AES

from aliyun_m3u8_downloader import crypto


def _pkcs5_pad(data: bytes, block: int = 16) -> bytes:
    pad = block - len(data) % block
    return data + bytes([pad]) * pad


def test_aes128_cbc_roundtrip():
    key = b"0123456789abcdef"
    iv = b"abcdef0123456789"
    plain = b"hello aliyun m3u8 downloader payload"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    enc = cipher.encrypt(_pkcs5_pad(plain))
    assert crypto.aes128_cbc_decrypt(enc, key, iv) == plain


def test_aes128_cbc_empty_iv_uses_key():
    key = b"0123456789abcdef"
    cipher = AES.new(key, AES.MODE_CBC, key)
    enc = cipher.encrypt(_pkcs5_pad(b"data"))
    assert crypto.aes128_cbc_decrypt(enc, key) == b"data"


def test_aes128_ecb_partial_block_preserved():
    key = b"0123456789abcdef"
    blocks = b"A" * 32  # two full blocks
    tail = b"XYZ"  # 3 trailing bytes, must stay untouched
    enc = AES.new(key, AES.MODE_ECB).encrypt(blocks) + tail
    out = crypto.aes128_ecb_decrypt(enc, key)
    assert out == blocks + tail


def test_encrypt_rand_is_base64():
    out = crypto.encrypt_rand(b"client-random-value")
    # RSA/PKCS1 output for the embedded 512-bit key is 64 bytes -> base64.
    assert len(base64.b64decode(out)) == 64


def test_decrypt_key_known_vector():
    # Build a self-consistent vector mirroring the Go key-exchange algorithm.
    r1 = "client-rand-123"
    server_plain = "server-rand-value"
    final_key_bytes = bytes(range(16))

    temp_key = hashlib.md5(r1.encode()).hexdigest()[8:24].encode()
    iv = temp_key
    rand_b64 = base64.b64encode(
        AES.new(temp_key, AES.MODE_CBC, iv).encrypt(_pkcs5_pad(server_plain.encode()))
    ).decode()

    temp_key2 = hashlib.md5((r1 + server_plain).encode()).hexdigest()[8:24].encode()
    final_b64_plain = base64.b64encode(final_key_bytes)  # what DecryptKey base64-decodes
    plain_b64 = base64.b64encode(
        AES.new(temp_key2, AES.MODE_CBC, iv).encrypt(_pkcs5_pad(final_b64_plain))
    ).decode()

    assert crypto.decrypt_key(r1, rand_b64, plain_b64) == final_key_bytes.hex()
