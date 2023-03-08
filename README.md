# File-Encryption-AES-CBC

AES_CBC_PKCS5_256KEYSIZE_128BLOCKSIZE for encryption

SHA256 for hashing

UTF8 for encoding

## ENCRYPTION

Encrypt(KEY, FILE)

    KEY = SHA(DECODE(KEY)) // FOR FIXED SIZE
    SHA(KEY) + SHA(FILE) + IV + AES(KEY, IV, FILE)

## DECRYPTION

DECRYPT(KEY, FILE)
    
    Check the password
    Decrypt cipher file
    Verify the checksum
