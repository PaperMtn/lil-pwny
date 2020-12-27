import binascii
import hashlib
import secrets


def hashify(input_string):
    """Converts the input string to a NTLM hash and returns the hash"""

    output = hashlib.new('md4', input_string.encode('utf-16le')).digest()

    return binascii.hexlify(output).decode('utf-8').upper()


def get_hashes(input_file):
    """Reads the input file of passwords, converts them to NTLM hashes, and returns them in a String"""

    output_dict = {}
    with open(input_file, 'r') as f:
        for item in f:
            if item:
                output_dict[hashify(item.strip())] = '0'

    return output_dict


def obfuscate(input_hash):
    """Further hashes the input NTLM hash"""

    output = hashlib.new('md4', (input_hash + secrets.token_hex(8)).encode('utf-16le')).digest()

    return binascii.hexlify(output).decode('utf-8').upper()

