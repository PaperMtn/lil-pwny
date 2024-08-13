class MalformedHIBPError(Exception):
    """ Exception raised when the HIBP file is not in the correct format
    """

    def __init__(self, message):
        super().__init__(f'{message} in the HIBP file is not formatted correctly. Make sure you are using '
                         f'the NTLM hashes in the format "hash:occurrences". These can be downloaded using '
                         f'this tool: https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader')


class HashingError(Exception):
    """ Base class for exceptions in this module."""
    pass


class FileReadError(HashingError):
    """ Exception raised for errors in the input file.

    Attributes:
        filename: The name of the input file which caused the error.
        message: Explanation of the error.
    """

    def __init__(self, filename, message='Error reading file'):
        """
        Args:
            filename: The name of the input file which caused the error.
            message: Explanation of the error. Defaults to "Error reading file".
        """
        self.filename = filename
        self.message = message
        super().__init__(f"{self.message}: {self.filename}")
