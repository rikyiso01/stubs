from typing import overload, Type
from Crypto.Cipher.blockalgo import MODE_CBC as cbc, MODE_ECB as ecb

class AESCipher:
    def decrypt(self, ciphertext: bytes) -> bytes: ...
    def encrypt(self, plaintext: bytes) -> bytes: ...

@overload
def new(key: bytes, mode: Type[MODE_ECB] = ...) -> AESCipher: ...
@overload
def new(key: bytes, mode: Type[MODE_CBC], IV: bytes) -> AESCipher: ...

MODE_ECB = ecb
MODE_CBC = cbc

block_size: int
key_size: tuple[int, int, int]
