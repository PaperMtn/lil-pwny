## [3.0.0] - 2024-07-22
### Added
- Updated logging
  - New stdout logging experience with colourised output that is easier to read.
  - Logging embedded in multiprocessing workers to provide matches as they are found, instead of all at the end.
  - DEBUG level logging for more verbose output and error tracing.
- Rebuilt to use Poetry for dependency management and packaging.
- Much better exception handling and robustness against errors

### Fixed
- Fixed broken support for MD4 (NTLM) hashing in the builtin Python `hashlib` library. This was causing the script to fail when hashing the NTLM hashes from the AD database. This has been fixed by using the `pycryptodome` library to hash the NTLM hashes.
  - This is fixed for obfuscation of hashes in the output, and for hashing the custom passwords list for comparison with AD users.
- Fixed issue where reading files in Windows would fail due to the default encoding being used. This has been fixed by implementing encoding detection.
- A number of errors that sometimes occurred when running on Windows

### Removed
- Removed the option to log to a file. This was not a useful feature, was hard to maintain, and can be achieved by redirecting stdout to a file.

## [2.0.0] - 2021-01-02
### Added
- Massive enhancements to make much better use of multiprocessing for the large HIBP password file, as well as more efficient importing and handling of Active Directory user hashes. 
- Updated directory structure to play more nicely with more OS versions and flavours, rather than installing in the `src` directory.
- Logging: Removed outdated text file output and implemented JSON formatted logging to either stdout or to .log file
- New option to obfuscate genuine password NTLM hashes in logging output. This is achieved by further hashing the hash with a randomly generated salt.
- Active Directory computer accounts are now not imported with AD user hashes. There is little value in assessing these, so no point importing them.

## [1.2.0] - 2020-03-22
Initial Release
