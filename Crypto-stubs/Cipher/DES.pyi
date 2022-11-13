from typing import Type, overload
from Crypto.Cipher.blockalgo import MODE_CBC as cbc, MODE_ECB as ecb

class DESCipher:
    def encrypt(self, plaintext: bytes) -> bytes: ...
    def decrypt(self, ciphertext: bytes) -> bytes: ...

@overload
def new(key: bytes, mode: Type[MODE_ECB] = ...) -> DESCipher: ...
@overload
def new(key: bytes, mode: Type[MODE_CBC], IV: bytes) -> DESCipher: ...

MODE_ECB = ecb
MODE_CBC = cbc

block_size: int
key_size: int
