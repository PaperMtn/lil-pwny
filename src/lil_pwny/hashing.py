import binascii
import hashlib
import secrets
from typing import Dict

from Crypto.Hash import MD4

from lil_pwny.exceptions import FileReadError


class Hashing(object):
    """ Class to handle hashing and obfuscation of strings
    """

    def __init__(self):
        self.salt = secrets.token_hex(8)

    @staticmethod
    def _hashify(input_string: str) -> str:
        """Converts the input string to a NTLM hash and returns the hash

        Args:
            input_string: string to be converted to NTLM hash
        Returns:
            Converted NTLM hash
        """

        hasher = MD4.new()
        hasher.update(input_string.encode('utf-16le'))
        output = hasher.digest()
        return binascii.hexlify(output).decode('utf-8').upper()

    def get_hashes(self, input_file: str) -> Dict[str, str]:
        """Reads the input file of passwords, converts them to NTLM hashes

        Args:
            input_file: file containing strings to convert to NTLM hashes
        Returns:
            Dict that replicates HIBP format: 'hash:occurrence_count'
        """

        output_dict = {}
        try:
            with open(input_file, 'r') as f:
                for item in f:
                    if item:
                        output_dict[self._hashify(item.strip())] = '0'
        except IOError as e:
            raise FileReadError(input_file, str(e))

        return output_dict

    def obfuscate(self, input_hash: str) -> str:
        """Further hashes the input NTLM hash with a random salt

        Args:
            input_hash: hash to be obfuscated
        Returns:
            String containing obfuscated hash
        """

        output = hashlib.new('sha1', (input_hash + self.salt).encode('utf-16le')).digest()

        return binascii.hexlify(output).decode('utf-8').upper()
