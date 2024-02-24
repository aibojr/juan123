import streamlit as st
import pandas as pd
import numpy as np

st.set_page_config(
        page_title="XOR Ciphe",
        page_icon="🔒",
        layout="wide"
    )

st.header("Welcome to XOR Cipher!🔒🔒")

st.sidebar.write("XOR Cipher!🔒🔒")


def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key, printing bits involved."""
    ciphertext = bytearray()
    for i in range(len(plaintext)):
        plaintext_byte = plaintext[i]
        key_byte = key[i % len(key)]
        # st.write(f"key_byte {key_byte}")
        # Perform XOR and st.write result
        cipher_byte = plaintext_byte ^ key_byte
        # st.write bits before XOR
        st.write(f"Plaintext byte: {format(plaintext_byte, '08b')} = {chr(plaintext_byte)}")
        st.write(f"Key byte:       {format(key_byte, '08b')} = {chr(key_byte)}")
        st.write(f"XOR result:     {format(cipher_byte, '08b')} = {chr(cipher_byte)}")
        st.write("-" * 20)  # Separator for clarity
        ciphertext.append(cipher_byte)
    return ciphertext

def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key.

    Args:
        ciphertext (bytes): The ciphertext to decrypt.
        key (bytes): The key used for encryption.

    Returns:
        bytes: The decrypted plaintext.
    """
    return xor_encrypt(ciphertext, key)  # XOR decryption is the same as encryption

# Example usage:
plaintext = bytes(st.text_area("Plaintext:").encode())
key = bytes(st.text_area("Key:").encode())

if st.button("Submit"):
    if plaintext != key:
        if len(plaintext.decode()) >= len(key.decode()):
            try:
                ciphertext = xor_encrypt(plaintext, key)
                st.write("Ciphertext:", ciphertext.decode())
                decrypted = xor_decrypt(ciphertext, key)
                st.write("Decrypted:", decrypted.decode())
            except:
                st.error("Invalid Key!")
        else:
            st.warning(f"Plaintext length should be equal or greater than the length of key")
    else:
        st.warning(f"Plaintext should not be equal to the key")