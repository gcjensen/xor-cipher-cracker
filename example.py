import sys
import binascii
from xor_cipher_cracker import XORCipherCracker

def convert_hex_to_binary(hex):
    hex = hex.replace(" ", "")
    binary = [
         '0000','0001','0010','0011',
         '0100','0101','0110','0111',
         '1000','1001','1010','1011',
         '1100','1101','1110','1111'
         ]
    binary_string = ''
    for i in range(len(hex)):
        binary_string += binary[int(hex[i], base=16)]
    return binary_string

if __name__ == '__main__':
    with open(sys.argv[1], 'r') as cipher_text_file:
        cipher_text = cipher_text_file.read().replace('\n', '')
        plain_text_chars = 'abcdefghijklmnopqrstuvwxyz .,-\'?_()!'
        cipher_text = convert_hex_to_binary(cipher_text)
        xor_cipher_cracker = XORCipherCracker(plain_text_chars)
        possible_decryptions = xor_cipher_cracker.crack(cipher_text)
        for key in possible_decryptions.keys():
            print('Decryption with key: ' + hex(int(key, 2)))
            print(binascii.unhexlify('%x' % possible_decryptions[key]))
