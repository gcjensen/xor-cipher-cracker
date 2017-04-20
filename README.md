# xor-cipher-cracker
An attack on the repeating key [XOR Cipher](https://en.wikipedia.org/wiki/XOR_cipher). The script attempts to decipher messages encrypted using the XOR Cipher with a repeating key.

## Example Usage
[example.py](/example.py) shows an example of using [xor_cipher_cracker.py](/xor_cipher_cracker.py) to decrypt the contents of [secret.hex](/secret.hex).

### Running example.py

`python example.py secret.hex`

## Methodology
The program works by running through a range of key lengths, slicing out sequential sections of the ciphertext equal in length to each one. The [Hamming distance](https://en.wikipedia.org/wiki/Hamming_distance) of each two section grouping of the text is then computed. The average Hamming distance for all sections of the ciphertext for each key length are found, and normalised by division by the key length. The smaller the resulting average hamming distance, the more likely a key length is to be correct.

The key space for keys of length n, where n is the most likely key length, is then generated. Each possible key is then XORed with each n-length block of ciphertext, before checking the resulting ASCII value matches one of a list of ‘legal’ characters (`’abcdefghijklmnopqrstuvwxyz .,-\’?_()!’`). The list of keys that produce only legal characters as the plaintext are then used to fully decrypt the ciphertext, which the program then returns with the corresponding keys.
