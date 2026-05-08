from hashlib import sha256

def make_message(nonce: bytes) -> bytes:
    return b"d.blanovschi@student.tudelft.nl\nhttps://github.com/dnbln/a\n" + nonce

def find_nonce():
    n = 0
    while True:
        message = make_message(n.to_bytes(8, "big"))
        hash = sha256(message).digest()
        if hash[0:3] == b"\x00\x00\x00" and hash[3] < 0x10:
            print("Found nonce:", n)
            print("Hash:", hash.hex())
            return n
        n += 1