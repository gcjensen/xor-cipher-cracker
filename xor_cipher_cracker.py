import sys
import operator
import binascii
import itertools

class XORCipherCracker():

    def __init__(self, plain_text_chars):
        self.plain_text_chars = plain_text_chars

    def crack(self, cipher_text_in_binary):
        key_lengths_with_probabilities = self.find_likely_key_lengths(cipher_text_in_binary)
        most_likely_key_length, probability = key_lengths_with_probabilities[0]

        # generate all possible n-bit keys
        possible_keys = ["".join(bit) for bit in itertools.product("01", repeat=most_likely_key_length)]

        keys = self.find_likely_keys(possible_keys, cipher_text_in_binary)
        print(len(keys))

        decryptions = {}
        for key in keys:
            possible_plain_text = self.decrypt_with_key(key, cipher_text_in_binary)
            if possible_plain_text:
                decryptions[key] = possible_plain_text

        return decryptions

    def find_likely_key_lengths(self, cipher_text):
        key_lengths = {}
        for key_length in range(2, 32):
            hamming_distances = 0
            position = 0
            counter = 0
            while(position + 2 * key_length <= len(cipher_text)):
                section_one = cipher_text[position:position+key_length]
                position += key_length
                section_two = cipher_text[position:position+key_length]
                position += key_length
                hamming_distances += self.calculate_hamming_distance(section_one, section_two)
                counter += 1
            average_hamming_distance = hamming_distances / float(counter)
            key_lengths[key_length] = average_hamming_distance / float(key_length)

        return sorted(key_lengths.iteritems(), key=operator.itemgetter(1), reverse=False)

    def calculate_hamming_distance(self, string_one, string_two):
        count = 0.0
        for i in range(len(string_one)):
            if string_one[i] != string_two[i]:
                count += 1
        return count

    def find_likely_keys(self, possible_keys, cipher_text_in_binary):
        keys = []
        count = 0
        for possible_key in possible_keys:
            count += 1
            if (count % 100000 == 0):
                print(count)
            if self.does_key_produce_only_legal_chars(possible_key, cipher_text_in_binary):
                keys.append(possible_key)
        return keys

    # checks to see if the key xors each key length block of cipher text
    # into only legal characters (passed in in the constructor)
    def does_key_produce_only_legal_chars(self, possible_key, cipher_text_in_binary):
        section = 0
        while section < len(cipher_text_in_binary):
            portion = cipher_text_in_binary[section: section+len(possible_key)]
            xor_result = int(possible_key, 2) ^ int(portion, 2)
            try:
                possible_plain_text_letter = binascii.unhexlify('%x' % xor_result)
                for char in list(possible_plain_text_letter):
                    if char.lower() not in self.plain_text_chars:
                        return False
            except TypeError:
                return False
            section += len(possible_key)
        return True

    def decrypt_with_key(self, key, cipher_text_in_binary):
        repeated_key = self.repeat_key_to_length(key, len(cipher_text_in_binary))
        return int(repeated_key, 2) ^ int(cipher_text_in_binary, 2)

    def repeat_key_to_length(self, key, cipher_text_length):
        repeat_key = (key * ((cipher_text_length / len(key)) + 1))
        return repeat_key[:cipher_text_length]

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
        # plain_text_chars = 'abcdefghijklmnopqrstuvwxyz .,-\'?_()!'
        plain_text_chars = 'abcdefghijklmnopqrstuvwxyz'
        # cipher_text = convert_hex_to_binary(cipher_text)
        cipher_text = '01001001 11000011 10110011 01010100 11000011 10110011 01011111 11000011 10110011 01000111 11000011 10110100 01000011 11000011 10101000 01001001 11000011 10101001 01000000 11000011 10110100 01010011 11000011 10100100 01010100 11000011 10100010 01000011 11000011 10110100 01000010 11000011 10110101 01001111 11000011 10100110 01001001 11000011 10100010 01000111 11000011 10101010 01010101 11000011 10111110 01010011 11000011 10110010 01001010 11000011 10101000 01011111 11000011 10100101 01010110 11000011 10101000 01001010 11000011 10110101 01011111 11000011 10110011 01010011 11000011 10101001 01010100 11000011 10110100 01000011 11000011 10100001 01000011 11000011 10110011 01000000 11000011 10101000 01001001 11000011 10101110 01001001 11000011 10110010 01001011 11000011 10101000 01001000 11000011 10110100 01101111 11000011 10101001 01011111 11000011 10100010 01010010 11000011 10101101 01001001 11000011 10110011 01001001 11000011 10110100'
        xor_cipher_cracker = XORCipherCracker(plain_text_chars)
        possible_decryptions = xor_cipher_cracker.crack(cipher_text.replace(" ", ""))
        for key in possible_decryptions.keys():
            print('Decryption with key: ' + hex(int(key, 2)))
            print(binascii.unhexlify('%x' % possible_decryptions[key]))
