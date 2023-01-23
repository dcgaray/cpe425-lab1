from pprint import pprint
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

# a global variable to hold the standard AES block size
block_size = AES.block_size

# encrypt our secret message with AES - Electronic Code Book
# return the key used to encrypt, and the actual encrypted message
def ecb_encrypt(msg):
    # get our AES information to encrypt our message
    key = get_random_bytes(block_size)
    cipher = AES.new(key, AES.MODE_ECB)

    # make sure to pad the message before trying to encrypt it
    ecb_encrypted_msg = cipher.encrypt(pad(msg, block_size))

    return key, ecb_encrypted_msg

# decrypte our secret message with AES - Electronic Code Book
# return our decrypted message, and then the decrypted message we messed up
def ecb_decrypt(key, encrypted_msg):
    # get our AES information to decrypt the message
    cipher = AES.new(key, AES.MODE_ECB)
    ecb_decrypted_msg = unpad(cipher.decrypt(encrypted_msg), block_size)

    # mess up a single bit in our byte string to see if there is any pattern-preservation/error propogation
    enc_msg_list = list(encrypted_msg) 
    enc_msg_list[13] = (enc_msg_list[13] ^ 13)
    error_msg = bytes(enc_msg_list)

    ecb_error_msg = unpad(cipher.decrypt(error_msg), block_size)

    return ecb_decrypted_msg, ecb_error_msg

# encrypt our secret message with AES - Ciphertext Block Chaining
# return the intialization vector, and key used to encrypt, as well as the ecrypted message
def cbc_encrypt(msg):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)
    intial_vector = cipher.iv

    # encrypted the message and make sure to pad it
    cbc_encrypted_msg = cipher.encrypt(pad(msg, block_size))

    return intial_vector, key, cbc_encrypted_msg 

# decrypte our secret message with AES - Ciphertext Block Chaining
# return our decrypted message, and then the decrypted message we messed up
def cbc_decrypt(intial_vector, cbc_key, encrypted_msg):
    cipher = AES.new(cbc_key, AES.MODE_CBC, iv=intial_vector)
    cbc_decrypted_msg = unpad(cipher.decrypt(encrypted_msg), block_size)

    # mess up a single bit in our byte string to see if there is any pattern-preservation/error propogation
    enc_msg_list = list(encrypted_msg) 
    enc_msg_list[13] = (enc_msg_list[25] ^ 13)
    error_msg = bytes(enc_msg_list)

    cbc_error_msg = unpad(cipher.decrypt(error_msg), block_size)

    return cbc_decrypted_msg, cbc_error_msg


# unlike the previous modes of AES encryption, Cipherfeed back doesn't require padding
# encrypt our secret message with AES - CipherFeedback mode
def cfb_encrypt(msg):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB)
    intial_vector = cipher.iv

    cfb_encrypted_msg = cipher.encrypt(msg)

    return intial_vector, key, cfb_encrypted_msg

# decrypt our secret message with AES - Cipherfeed back mode
# return our decrypted message, and then the decrypted message we messed up
def cfb_decrypt(ctr_iv, ctr_key, encrypted_msg):
    cipher = AES.new(ctr_key, AES.MODE_CFB, iv=ctr_iv)
    cfb_decrypted_message = cipher.decrypt(encrypted_msg)

    # mess up a single bit in our byte string to see if there is any pattern-preservation/error propogation
    enc_msg_list = list(encrypted_msg) 
    enc_msg_list[13] = (enc_msg_list[25] ^ 13)
    error_msg = bytes(enc_msg_list)

    cfb_error_msg = cipher.decrypt(error_msg)

    return cfb_decrypted_message, cfb_error_msg

# unlike the previous modes of AES encryption, Output Feedback Mode back doesn't require padding
# encrypt our secret message with AES - Output Feedback
def ofb_encrypt(msg):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_OFB)
    intial_vector = cipher.iv

    ofb_encrypted_msg = cipher.encrypt(msg)

    return intial_vector, key, ofb_encrypted_msg

# decrypt our secret message with AES - Outpur Feedback mode
# return our decrypted message, and then the decrypted message we messed up
def ofb_decrypt(ofb_iv, ofb_key, encrypted_msg):
    cipher = AES.new(ofb_key, AES.MODE_OFB, iv=ofb_iv)
    ofb_decrypted_message = cipher.decrypt(encrypted_msg)

    # mess up a single bit in our byte string to see if there is any pattern-preservation/error propogation
    enc_msg_list = list(encrypted_msg) 
    enc_msg_list[13] = (enc_msg_list[25] ^ 13)
    error_msg = bytes(enc_msg_list)

    ofb_error_msg = cipher.decrypt(error_msg)

    return ofb_decrypted_message, ofb_error_msg

# encrypt our secret message with AES - CounTeR mode
# return the nonce, and key used to encrypt, as well as the ecrypted message
def ctr_encrypt(msg):
    key = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CTR)
    ctr_nonce = cipher.nonce
    ctr_encrypted_msg = cipher.encrypt(msg)

    return ctr_nonce, key, ctr_encrypted_msg

# decrypt our secret message with AES - CounTeR mode
# return our decrypted message, and then the decrypted message we messed up
def ctr_decrypt(ctr_nonce, ctr_key, encrypted_msg):
    cipher = AES.new(ctr_key, AES.MODE_CTR, nonce=ctr_nonce)
    ctr_decrypted_msg = cipher.decrypt(encrypted_msg)

    # mess up a single bit in our byte string to see if there is any pattern-preservation/error propogation
    enc_msg_list = list(encrypted_msg) 
    enc_msg_list[13] = (enc_msg_list[25] ^ 13)
    error_msg = bytes(enc_msg_list)

    ctr_error_msg = cipher.decrypt(error_msg)

    return ctr_decrypted_msg, ctr_error_msg

# checks a byte string for patterns
def check_for_patterns(encrypted_msg):
    too_many_repeats = 10

    # create a list of all the different bytes in the message
    byte_list = list(encrypted_msg)
    pattern_dict = dict.fromkeys(byte_list, 0)

    # go through every byte in the message and increment how many times it's seen
    for byte in byte_list:
        pattern_dict[byte] += 1

    # find out how many bytes are repeated
    repeated_bytes = [] 
    for pattern, freq in pattern_dict.items():
        if freq >= 4: 
            repeated_bytes.append(pattern)

    # if there too many repeats, it's preserving patterns
    if len(repeated_bytes) > too_many_repeats:
        return True
    else:
        return False

# check to see if flipping a bit in the code propogated errors
def check_for_error_prop(decrypted_msg, error_msg):
    block_size = AES.block_size + 1

    # split the byte strings into lists based off a block size of 17
    blocked_decrypted_msg = [str(decrypted_msg)[i:i+block_size] for i in range(0, len(decrypted_msg), block_size)]
    blocked_error_msg = [str(error_msg)[i:i+block_size] for i in range(0, len(error_msg), block_size)]

    wrong_block_counter = 0
    for block in blocked_error_msg:
        if block not in blocked_decrypted_msg:
            wrong_block_counter += 1
    
    #print(blocked_decrypted_msg)
    #print(blocked_error_msg)

    # okay, so when i was breaking the string up the "b'---'", the b'' was still showing up
    # alongside that, looking at how ECB works(a mode of AES i know doesn't propogate errors, the first 4 blocks would be messed up)
    # given that I flipped a byte in all the first block for every mode, I used 4 as my standard for the wrong amount of blocks
    if wrong_block_counter > 4: 
        return True
    else:
        return False

# run all of the different encryptions that we were asked to evaluate
def main():
    # make sure our characters come in the AES block size for testing purposes
    lots_of_a = "a" * 8
    lots_of_b = "b" * 16
    lots_of_c = "sea" * 64

    section_marker = "-_" * 16

    # generate our secret message that we want to keep hidden
    secret_msg = "%s%s%s" % (lots_of_a, lots_of_b, lots_of_c)
    secret_msg_bytes = bytes(secret_msg, 'utf-8')

    ##########################
    # run the ECB encryption # 
    ecb_key, ecb_encrypted_msg = ecb_encrypt(secret_msg_bytes)
    print(f"The ECB encrypted message is :\n{ecb_encrypted_msg}")

    # run our ECB decryption, both the correct version and the messed up version
    ecb_decrypted_msg, ecb_error_msg = ecb_decrypt(ecb_key, ecb_encrypted_msg)
    print(f"The ECB dencrypted message is :\n{ecb_decrypted_msg}")
    print(f"The bit flipped ECB decrypted message is:{ecb_error_msg}")
    print(f"Is there Pattern Preservation?: {check_for_patterns(ecb_encrypted_msg)}")
    print(f"is there Error Propogation?: {check_for_error_prop(ecb_decrypted_msg, ecb_error_msg)}")
    print(f"{section_marker}\n")

    ##########################
    # run the CBC encryption #
    cbc_iv, cbc_key, cbc_encrypted_msg = cbc_encrypt(secret_msg_bytes)
    print(f"The CBC encrypted message is :\n{cbc_encrypted_msg}")

    # run our CBC decryption, both the correct version and the messed up version
    cbc_decrypted_msg, cbc_error_msg = cbc_decrypt(cbc_iv, cbc_key, cbc_encrypted_msg)
    print(f"The CBC dencrypted message is :\n{cbc_decrypted_msg}")
    print(f"The bit flipped CBC decrypted message is:{cbc_error_msg}")
    print(f"Is there Pattern Preservation?: {check_for_patterns(cbc_encrypted_msg)}")
    print(f"is there Error Propogation?: {check_for_error_prop(cbc_decrypted_msg, cbc_error_msg)}")
    print(f"{section_marker}\n")

    ##########################################
    # run the CipherText Feedback decryption #
    cfb_iv, cfb_key, cfb_encrypted_msg = cfb_encrypt(secret_msg_bytes)
    print(f"The CFB encrypted message is :\n{cfb_encrypted_msg}")

    # run the CipherText decryption
    cfb_decrypted_msg, cfb_error_msg = cfb_decrypt(cfb_iv, cfb_key, cfb_encrypted_msg)
    print(f"The CFB dencrypted message is :\n{cfb_decrypted_msg}")
    print(f"The bit flipped CFB decrypted message is:{cfb_error_msg}")
    print(f"Is there Pattern Preservation?: {check_for_patterns(cfb_encrypted_msg)}")
    print(f"is there Error Propogation?: {check_for_error_prop(cfb_decrypted_msg, cfb_error_msg)}")
    print(f"{section_marker}\n")

    ###################################
    # run the OutputFeed mode encryption #
    ofb_iv, ofb_key, ofb_encrypted_msg = ofb_encrypt(secret_msg_bytes)
    print(f"The OFB encrypted message is :\n{ofb_encrypted_msg}")

    # run Output Feedback mode decryption
    ofb_decrypted_msg, ofb_error_msg = ofb_decrypt(ofb_iv, ofb_key, ofb_encrypted_msg)
    print(f"The OFB dencrypted message is :\n{ofb_decrypted_msg}")
    print(f"The bit flipped OFB decrypted message is:{ofb_error_msg}")
    print(f"Is there Pattern Preservation?: {check_for_patterns(ofb_encrypted_msg)}")
    print(f"is there Error Propogation?: {check_for_error_prop(ofb_decrypted_msg, ofb_error_msg)}")
    print(f"{section_marker}\n")

    ###################################
    # run the CounTeR mode decryption #
    ctr_nonce, ctr_key, ctr_encrypted_msg = ctr_encrypt(secret_msg_bytes)
    print(f"The CTR encrypted message is :\n{ctr_encrypted_msg}")

    # run the CounTer mode encryption
    ctr_decrypted_msg, ctr_error_msg = ctr_decrypt(ctr_nonce, ctr_key, ctr_encrypted_msg)
    print(f"The CTR dencrypted message is :\n{ctr_decrypted_msg}")
    print(f"The bit flipped CTR decrypted message is:{ctr_error_msg}")
    print(f"Is there Pattern Preservation?: {check_for_patterns(ctr_encrypted_msg)}")
    print(f"is there Error Propogation?: {check_for_error_prop(ctr_decrypted_msg, ctr_error_msg)}")







if __name__ == "__main__":
    main()