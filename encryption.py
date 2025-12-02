# def encrypt(text, shift=3):
#     result = ""
#     for char in text:
#         result += chr(ord(char) + shift)
#     return result

# def decrypt(text, shift=3):
#     result = ""
#     for char in text:
#         result += chr(ord(char) - shift)
#     return result

import base64

# -------------------------------
# VIGENERE + BASE64 ENCRYPTION
# -------------------------------

KEY = "MYSECRETKEY"    # you can change this, keep alphabetic


def vigenere_encrypt(text, key=KEY):
    """Basic Vigenere cipher."""
    result = ""
    key = key.upper()
    k = 0

    for char in text:
        shift = ord(key[k % len(key)]) % 26
        result += chr(ord(char) + shift)
        k += 1

    return result


def vigenere_decrypt(text, key=KEY):
    """Reverses Vigenere cipher."""
    result = ""
    key = key.upper()
    k = 0

    for char in text:
        shift = ord(key[k % len(key)]) % 26
        result += chr(ord(char) - shift)
        k += 1

    return result


def encrypt(text, key=KEY):
    """Vigenere → Base64"""
    # Step 1: Vigenere
    vig = vigenere_encrypt(text, key)
    # Step 2: Base64 wrapping
    b64 = base64.b64encode(vig.encode()).decode()
    return b64


def decrypt(text, key=KEY):
    """Base64 → Vigenere"""
    # Step 1: Base64 decode
    vig = base64.b64decode(text).decode()
    # Step 2: Vigenere decrypt
    original = vigenere_decrypt(vig, key)
    return original

