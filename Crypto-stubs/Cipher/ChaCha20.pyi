class ChaCha20Cipher:
    def encrypt(self, plaintext: bytes) -> bytes: ...
    def decrypt(self, ciphertext: bytes) -> bytes: ...

def new(*, key: bytes, nonce: int = ...) -> ChaCha20Cipher: ...

block_size: int
key_size: int
