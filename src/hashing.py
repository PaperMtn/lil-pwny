import binascii
import hashlib

"""This module takes an input file of passwords and produces 
an output file of the NTLM hashes of those passwords"""


def hashify(input_string):
    """Converts the input string to a NTLM hash and returns the hash"""

    output = hashlib.new('md4', input_string.encode('utf-16le')).digest()

    return binascii.hexlify(output).decode('utf-8').upper()


def get_hashes(input_file):
    """Reads the input file of passwords and returns them in a String"""

    pwds = []
    with open(input_file, 'r') as f:
        for item in f:
            pwds.append(hashify(item.strip()))

    output = ' '.join(pwds)

    return output

