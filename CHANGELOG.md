## 2.0.0 - 2021-01-02
### Added
- Massive enhancements to make much better use of multiprocessing for the large HIBP password file, as well as more efficient importing and handling of Active Directory user hashes. 
- Updated directory structure to play more nicely with more OS versions and flavours, rather than installing in the `src` directory.
- Logging: Removed outdated text file output and implemented JSON formatted logging to either stdout or to .log file
- New option to obfuscate genuine password NTLM hashes in logging output. This is achieved by further hashing the hash with a randomly generated salt.
- Active Directory computer accounts are now not imported with AD user hashes. There is little value in assessing these, so no point importing them.

## 1.2.0 - 2020-03-22
Initial Release
