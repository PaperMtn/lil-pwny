import binascii
import hashlib
import secrets
from typing import List

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

    def get_hashes(self, password_list: str) -> List[str]:
        """Converts a list of strings to NTLM hashes

        Args:
            password_list: file containing strings to convert to NTLM hashes
        Returns:
            List of NTLM hashes of the passwords
        """

        return [self._hashify(password) for password in password_list]

    def obfuscate(self, input_hash: str) -> str:
        """Further hashes the input NTLM hash with a random salt

        Args:
            input_hash: hash to be obfuscated
        Returns:
            String containing obfuscated hash
        """

        output = hashlib.new('sha1', (input_hash + self.salt).encode('utf-16le')).digest()

        return binascii.hexlify(output).decode('utf-8').upper()
