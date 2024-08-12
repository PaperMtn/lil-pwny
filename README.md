<img src="https://i.imgur.com/Q0pPSjN.png" width="450">

# Lil Pwny
![Python 2.7 and 3 compatible](https://img.shields.io/pypi/pyversions/lil-pwny)
![PyPI version](https://img.shields.io/pypi/v/lil-pwny.svg)
![License: MIT](https://img.shields.io/pypi/l/lil-pwny.svg)

Fast offline auditing of Active Directory passwords using Python.

## About Lil Pwny
Lil Pwny is a Python application to perform an offline audit of NTLM hashes of users' passwords, recovered from Active Directory, against known compromised passwords from Have I Been Pwned. Results will be output in JSON format containing the username, matching hash (can be obfuscated), and how many times the matching password has been seen in HIBP

More information about Lil Pwny can be found [on my blog](https://papermtn.co.uk/category/tools/lil-pwny/)

## Features

- **Custom Password Auditing**: Ability to provide a list of your own custom passwords to check AD users against. This allows you to check user passwords against passwords relevant to your organisation that you suspect people might be using. 
  - Pass a .txt file with the plaintext passwords you want to search for, these are then NTLM hashed and AD hashes are then compared with this as well as the HIBP hashes.
- **Detect Duplicates**: Return a list of accounts using the same passwords. Useful for finding users using the same password for their administrative and standard accounts.
- **Obfuscated Output**: Obfuscate hashes in output, for if you don't want to handle or store live user NTLM hashes.

### Custom Password List Enhancement
Lil Pwny provides the functionality to enhance your custom password list by adding commonly used variants of your custom passwords. These include:
- Passwords with common 'leetspeak' substitutions (e.g. `P@ssw0rd`)
- Uppercase versions of the password, and uppercase first characters (e.g. `PASSWORD`, `Password`)
- Passwords with common special characters appended or prepended (e.g. `password!`, `!password`)
- Passwords padded with common alphanumeric characters, special characters and repetitions of themselves to make them meet a given minimum length (e.g. `password123!`, `!passwordabc`, `passwordpassword`)
  - You pass your desired minimum password length to Lil Pwny when selecting the custom list enhancement option
- Passwords with dates appended starting from the year 1950 up to 10 years from today's date (e.g. `password1950`, `password2034`)

A custom password list of 100 plaintext passwords generates 49848660 variations.
## Resources
This application has been developed to make the most of multiprocessing in Python, with the aim of it working as fast as possible on consumer level hardware.

Because it uses multiprocessing, the more cores you have available, the faster Lil Pwny should run. I have still had very good results with a low number of logical cores:
- Test env of ~8500 AD accounts and HIBP list of 613,584,246 hashes:
    - 6 logical cores - 0:05:57.640813
    - 12 logical cores - 0:04:28.579201

## Output
Lil Pwny will output results as either to stdout or JSON:

```json
{"localtime": "2021-00-00 00:00:00,000", "level": "NOTIFY", "source": "Lil Pwny", "match_type": "hibp", "detection_data": {"username": "RICKON.STARK", "hash": "0C02C50B2B08F2979DFDE12EDA472FC1", "matches_in_hibp": "24230577", "obfuscated": "True"}}
```
You can redirect the JSON output of Lil Pwny to file:
```commandline
lil-pwny -ad ... > lil-pwny-results.json 
```

This JSON formatted logging can be easily ingested in to a SIEM or other log analysis tool, and can be fed to other scripts or platforms for automated resolution actions.

## Installation
Install via pip
```bash
pip install lil-pwny
```

## Usage
Lil-pwny will be installed as a global command, use as follows:

```
usage: lil-pwny [-h] -hibp HIBP [-v] [-c CUSTOM] [-custom-enhance CUSTOM_ENHANCE] -ad AD_HASHES [-d] [-output {file,stdout,json}] [-o] [--debug]

Fast offline auditing of Active Directory passwords using Python

options:
  -h, --help            show this help message and exit
  -hibp HIBP, --hibp HIBP
                        The .txt file containing HIBP NTLM hashes
  -v, --version         show program's version number and exit
  -c CUSTOM, --custom CUSTOM
                        .txt file containing additional custom passwords to check for
  -custom-enhance CUSTOM_ENHANCE, --custom-enhance CUSTOM_ENHANCE
                        generate an enhanced custom password list based on the provided custom password list. Must be used with -c/--custom flag. The enhanced list will stored in memory and not written to disk. Provide the minimum length of the passwords you want. Default is 8
  -ad AD_HASHES, --ad-hashes AD_HASHES
                        The .txt file containing NTLM hashes from AD users
  -d, --duplicates      Output a list of duplicate password users
  -output {file,stdout,json}, --output {file,stdout,json}
                        Where to send results
  -o, --obfuscate       Obfuscate hashes from discovered matches by hashing with a random salt
  --debug               Turn on debug level logging
```

Example:
```bash
lil-pwny -hibp ~/hibp_hashes.txt -ad ~/ad_user_hashes.txt -c ~/custom_passwords.txt -output stdout -do
```



## Getting input files
### Step 1: Get an IFM AD database dump

On a domain controller use `ntdsutil` to generate an IFM dump of your AD domain. Run the following in an elevated PowerShell window:

```bash
ntdsutil
activate instance ntds
ifm
create full **output path**
```

### Step 2: Recover NTLM hashes from this output

To recover the NTLM hashes from the AD IFM data, the Powershell module [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) is required.

Once installed, use the SYSTEM hive in the IFM data to recover the hashes in the format `usernme:hash` and save them to the file `ad_ntlm_hashes.txt`

```bash
$bootKey = Get-BootKey -SystemHivePath '.\registry\SYSTEM'
Get-ADDBAccount -All -DBPath '.\Active Directory\ntds.dit' -BootKey $bootKey | Format-Custom -View HashcatNT | Out-File ad_ntlm_hashes.txt -Encoding ASCII
```

### Step 3: Download the latest HIBP hash file
The file can be downloaded from the HIBP API using a .net utility  [here](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)

## Resources
- [ntdsutil & IFM](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732530(v=ws.11))
