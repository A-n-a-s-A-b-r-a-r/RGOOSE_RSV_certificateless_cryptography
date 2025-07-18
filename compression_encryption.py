import zlib , os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HEADER_LENGTH = 18  # Length of the PDU header (example)
NONCE_SIZE = 12  # Nonce size for AES-GCM in bytes
TAG_SIZE = 16  # Tag size for AES-GCM in bytes
AES_KEY_SIZE = 32  # AES-256 key size in bytes

from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def compress_data(data: bytes) -> bytes:
    return zlib.compress(data)

def decompress_data(data: bytes) -> bytes:
    return zlib.decompress(data)

key = b'\xe3\x1e\xc3G\x8f\x98|\x15u\xf3`\xf2\xdc7\xe1 \x00\xdc\x1a\x85\t6B\x13\x8d\xcd\xfcu\xcd\x08{A'

def generate_hmac_cryptography(key, message):
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(bytes(message))  # Convert list of integers to bytes
    return h.finalize()  # Return raw bytes (not hex)
