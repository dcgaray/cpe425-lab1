import time
import itertools
from Crypto.Cipher import AES
from Crypto.Cipher import ARC4


# takes a message in plaintext, and will encrypt the message using AES in the EAX mode
#   EAX mode was chosen because it allows the reciever to detect any unauthorized modifications
def aes_encrypt_message(secret_msg):
    # 16 bytes is 128 bits and the lab spec asked the key be 128 "1"s
    key = b'\xff' * 16 
    cipher = AES.new(key, AES.MODE_EAX)

    # encrypt_and_digest will return a tuple containing: 1. ciphertext(in bytes); 2.MAC tag(in bytes) 
    aes_encrypted_msg, tag = cipher.encrypt_and_digest(secret_msg)
    aes_encryption_info = [cipher.nonce, tag]

    return key, aes_encryption_info, aes_encrypted_msg

# takes in a key, and the name of a file that holds encrypted information
def aes_decrypt_message(key, aes_info, encrypted_msg):
    aes_nonce = aes_info[0]
    aes_tag = aes_info[1]

    cipher = AES.new(key, AES.MODE_EAX, aes_nonce)
    decrypted_msg = cipher.decrypt_and_verify(encrypted_msg, aes_tag)

    return decrypted_msg


# encrypt our message using
def rc4_encrypt(plaintext_msg):
    # the lab said we need 40 1's
    key = b"\xff" * 5

    cipher = ARC4.new(key)
    encrypted_msg = cipher.encrypt(plaintext_msg)

    return key, encrypted_msg

def rc4_decrypt(key, encrypted_msg):
    cipher = ARC4.new(key)
    decrypted_msg = cipher.decrypt(encrypted_msg)

    return decrypted_msg

# go through and try every possible permutation
def brute_force_crack_rc4(encrypted_msg, decrypted_msg, key_len):
    all_posible_keys = itertools.product(range(256), repeat=key_len)
    for posible_key in all_posible_keys:
        # convert key tuple to bytes
        key = bytes(posible_key)
        cipher = ARC4.new(key)
        posible_decryption = cipher.decrypt(encrypted_msg)

        if decrypted_msg == posible_decryption:
            print(f"Found it!...the key was {key}")
            break

    return posible_decryption

# using AES in EAX mode will encrypt, and decrypt a message
#   then, using RC4 encrypt a message and decrypt it...
#       finally, if you really want you can try to bruteforce decrypt the RC4 message
def main():

    # keep in mind this will take forever.
    bruteforce = False

    # the message we wish to encrypt with AES, which must be passed in a binary string
    secret_msg = b"this is the wireless security lab"

    aes_key, aes_info, aes_encrypted_msg = aes_encrypt_message(secret_msg)
    aes_decrypted_msg = aes_decrypt_message(aes_key, aes_info, aes_encrypted_msg) 

    print(f"The AES encrypted messages says: {aes_encrypted_msg}")
    print(f"Decrypted, the message says: {aes_decrypted_msg}")

    print("------------------")

    rc4_key, rc4_encrypted_msg = rc4_encrypt(secret_msg)
    rc4_decrypted_msg = rc4_decrypt(rc4_key, rc4_encrypted_msg)

    print(f"The RC4 encrypted message says: {rc4_encrypted_msg}")
    print(f"The RC4 decrypted message says: {rc4_decrypted_msg}")
    
    if bruteforce == True:
        print("------------------")
        print("Attempting to brute force the decrytion of the RC4 text...")
        start_time = time.time()
        bruteforce_decrypted_msg_rc4 = brute_force_crack_rc4(rc4_encrypted_msg, rc4_decrypted_msg, rc4_key)
        end_time = time.time()
        print(f"It took {round(end_time-start_time, 2)} seconds to brute force crack the RC4 encrption")
        print(f"They wanted to keep this secret message from us: {bruteforce_decrypted_msg_rc4}")





if __name__ == "__main__":
    main()


    