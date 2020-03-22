# Lil Pwny
![Python 2.7 and 3 compatible](https://img.shields.io/badge/python-2.7%2C%203.x-blue.svg)
![PyPI version](https://img.shields.io/pypi/v/lil-pwny.svg)
![License: MIT](https://img.shields.io/pypi/l/lil-pwny.svg)

A multiprocessing approach to auditing Active Directory passwords using Python.

## About Lil Pwny

Lil Pwny is a Python application to perform an offline audit of NTLM hashes of users' passwords, recovered from Active Directory, against known compromised passwords from Have I Been Pwned. The usernames of any accounts matching HIBP will be returned in a .txt file

There are also additional features:
- Ability to provide a list of your own passwords to check AD users against. This allows you to check user passwords against passwords relevant to your organisation that you suspect people might be using. These are NTLM hashed, and AD hashes are then compared with this as well as the HIBP hashes.
- Return a list of accounts using the same passwords. Useful for finding users using the same password for their administrative and standard accounts.

More information about Lil Pwny can be found [on my blog](https://papermtn.co.uk/)

## Recommendations
This application was developed to ideally run on high resource infrastructure to make the most of Python multiprocessing. It will run on desktop level hardware, but the more cores you use, the faster the audit will run.

## Installation
Install via pip
```bash
pip install lil-pwny
```

## Usage
Lil-pwny will be installed as a global command, use as follows:

```bash
usage: lil-pwny [-h] -hibp HIBP [-a A] -ad AD_HASHES [-d] [-m] [-o OUTPUT]

optional arguments:
  -hibp, --hibp-path    The HIBP .txt file of NTLM hashes
  -a, --a               .txt file containing additional passwords to check for
  -ad, --ad-hashes      The NTLM hashes from of AD users
  -d, --find-duplicates Output a list of duplicate password users
  -m, --memory          Load HIBP hash list into memory (over 24GB RAM
                        required)
  -o, --out-path        Set output path. Uses working dir when not set
```

Example:
```bash
lil-pwny -hibp ~/hibp_hashes.txt -ad ~/ad_ntlm_hashes.txt -a ~/additional_passwords.txt -o ~/Desktop/Output -m -d
```

use of the `-m` flag will load the HIBP hashes into memory, which will allow for faster searching. Note this will require at least 24GB of available memory.

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
The file can be downloaded from [here](https://downloads.pwnedpasswords.com/passwords/pwned-passwords-ntlm-ordered-by-count-v5.7z)

The latest version of the hash file contains around 551 million hashes.

## Resources
- [ntdsutil & IFM](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732530(v=ws.11))
