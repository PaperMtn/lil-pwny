import binascii
import hashlib
import secrets
from typing import List
from multiprocessing import Pool, cpu_count


from Crypto.Hash import MD4


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

    def _process_password(self, password: str) -> str:
        return f'{self._hashify(password)}:0:{password}'

    def get_hashes(self, password_list: List[str]) -> List[str]:
        """Converts a list of strings to NTLM hashes using multiprocessing

        Args:
            password_list: list of strings to convert to NTLM hashes
        Returns:
            List of NTLM hashes of the passwords
        """
        with Pool(cpu_count()) as pool:
            hashes = pool.map(self._process_password, password_list)
        return hashes

    def obfuscate(self, input_hash: str) -> str:
        """Further hashes the input NTLM hash with a random salt

        Args:
            input_hash: hash to be obfuscated
        Returns:
            String containing obfuscated hash
        """

        output = hashlib.new('sha1', (input_hash + self.salt).encode('utf-16le')).digest()

        return binascii.hexlify(output).decode('utf-8').upper()
