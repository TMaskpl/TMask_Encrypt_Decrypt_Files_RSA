#!/usr/bin/python

# pip3 install pycryptodome

# sudo apt-get install build-essential python3-dev
# pip3 install pycryptodomex
# pip3 install pycryptodome-test-vectors
# python3 - m Cryptodome.SelfTest


from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Cryptodome.Random import get_random_bytes
import rsa
import os
from random import randbytes

# --- TST ---
def testRSA():
    
    (pubkey, privkey) = rsa.newkeys(1024)  # 2048, 4096
    
    print('Prvkey')
    print(privkey)
    print('Pubkey')
    print(pubkey)
    
    message = b'TMask.pl'
    
    crypto = rsa.encrypt(message, pubkey)
    print('Encrypt message')
    print(crypto)
    decrypt = rsa.decrypt(crypto, privkey)
    print('Message decrypted')
    print(decrypt.decode())


# Zmienne       

file_path = 'd_dst.json'

path_prvkey = 'prv_key.txt'
path_pubkey = 'pub_key.txt'

# Tworzenie pary kluczy
def generateRSAKeyPair(passphrase):
    assert passphrase is not None
    key = RSA.generate(2048)
    private_key = key.exportKey(passphrase=passphrase,
                                pkcs=8,
                                protection='scryptAndAES128-CBC'
                                )
    public_key = key.publickey().exportKey()
    return private_key, public_key

def saveKeyToFiles(passphrase, prvkey, pubkey):
    private, public = generateRSAKeyPair(passphrase)
    
    with open(prvkey, 'wb') as f:
        f.write(private)
    with open(pubkey, 'wb') as f:
        f.write(public)
        
def encrypt(key, src_file_path, encrypted_file_path):
    rsa_key = RSA.import_key(key)
    
    with open(encrypted_file_path, 'wb') as f:
        session_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        f.write(cipher_rsa.encrypt(session_key))
        
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        
        with open(src_file_path, 'rb') as infile:
            data = infile.read()
            ciphertext, digest = cipher_aes.encrypt_and_digest(data)
            
            f.write(cipher_aes.nonce)
            f.write(digest)
            f.write(ciphertext)

def decrypt(key, passphrase, encrypted_file_path):
    rsa_key = RSA.import_key(key, passphrase=passphrase)
    with open(encrypted_file_path, 'rb') as f:
        enc_session_key, nonce, digest, ciphertext = [ f.read(x)
                                                      for x in (rsa_key.size_in_bytes(), 16, 16, -1)
                                                      ]
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        
        data = cipher_aes.decrypt_and_verify(ciphertext, digest)
        
        return data

# Zaszyfruj wybranym kluczem publicznym
def encrypyPublicKey(pubkey, src_file_path, src_file_path_encrypted):
    with open(pubkey, 'rb') as f:
        public_key = f.read()
        encrypt(public_key, src_file_path, src_file_path_encrypted)

# Odszyfruj wybranym kluczm prywatnym
def decryptPrivateKey(key, password, src_file_path_encrypted, src_file_path_decrypted):
    with open(key, 'rb') as g:
        private_key = g.read()
        plain_data = decrypt(private_key, password, src_file_path_encrypted)
        with open(src_file_path_decrypted, 'wb') as f:
            f.write(plain_data)
        
        
        
        
# Funkcja główna
def main():
    saveKeyToFiles('superTajneh@sl0', 'tmask_prv.key', 'tmask_pub.key')
    encrypyPublicKey('tmask_pub.key', 'd_dst.json', 'd_dst.json.asc')
    decryptPrivateKey('tmask_prv.key', 'superTajneh@sl0',
                      'd_dst.json.asc', 'd_dst.json.dec')
        
if __name__ == "__main__":
    main()
