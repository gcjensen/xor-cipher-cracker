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

        decryptions = {}
        for key in keys:
            possible_plain_text = self.decrypt_with_key(key, cipher_text_in_binary)
            if possible_plain_text:
                decryptions[key] = possible_plain_text

        return decryptions

    def find_likely_key_lengths(self, cipher_text):
        possible_key_lengths = {}
        for key_length in range(2, 32):
            hamming_distances = position = counter = 0
            # calculate the hamming distance between sequential pieces of ciphertext,
            # with the size of the pieces being determined by the key length being tested.
            while(position + 2 * key_length <= len(cipher_text)):
                section_one = cipher_text[position:position+key_length]
                position += key_length
                section_two = cipher_text[position:position+key_length]
                position += key_length
                hamming_distances += self.calculate_hamming_distance(section_one, section_two)
                counter += 1
            average_hamming_distance = hamming_distances / float(counter)

            # normalise the average hamming distance by dividing by key length
            possible_key_lengths[key_length] = average_hamming_distance / float(key_length)

        # key length with lowest normalised average hamming distance is most likely to be the correct one
        return sorted(possible_key_lengths.iteritems(), key=operator.itemgetter(1), reverse=False)

    # https://en.wikipedia.org/wiki/Hamming_distance
    def calculate_hamming_distance(self, string_one, string_two):
        count = 0.0
        for i in range(len(string_one)):
            if string_one[i] != string_two[i]:
                count += 1
        return count

    # find the keys that produce a plaintext containing only the legal characters
    def find_likely_keys(self, possible_keys, cipher_text_in_binary):
        keys = []
        for possible_key in possible_keys:
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
