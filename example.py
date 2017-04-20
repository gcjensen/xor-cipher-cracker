import sys
import binascii
from xor_cipher_cracker import XORCipherCracker

def convert_hex_file_to_binary_string(hex_file):
    hex_string = binascii.hexlify(hex_file).replace('\n', '')
    binary = [
         '0000','0001','0010','0011',
         '0100','0101','0110','0111',
         '1000','1001','1010','1011',
         '1100','1101','1110','1111'
         ]
    binary_string = ''
    for i in range(len(hex_string)):
        binary_string += binary[int(hex_string[i], base=16)]
    return binary_string

if __name__ == '__main__':
    with open(sys.argv[1], 'r') as hex_file:
        cipher_text_in_binary = convert_hex_file_to_binary_string(hex_file.read())
        # the list of characters we believe the plaintext to contain
        plain_text_chars = 'abcdefghijklmnopqrstuvwxyz .,-\'?_()!'
        xor_cipher_cracker = XORCipherCracker(plain_text_chars)
        possible_decryptions = xor_cipher_cracker.crack(cipher_text_in_binary)
        for key in possible_decryptions.keys():
            print('Decryption with key: ' + hex(int(key, 2)))
            print(binascii.unhexlify('%x' % possible_decryptions[key]))
