# Little Pwny

A multiprocessing approach to auditing Active Directory passwords using Python.

## About

This is a Python application to audit NTLM hashes of users' passwords, recovered from Active Directory, against known compromised passwords from Have I Been Pwned.

## Recommendations
This application was developed to run on high resource infrastructure to make the most of Python multiprocessing 

## Step 1: Get an IFM AD database dump

On a domain controller use `ntdsutil` to generate an IFM dump of your AD domain. Run the following in an elevated Powershell window:
```
ntdsutil
activate instance ntds
ifm
create full <<output path>>
```
## Step 2: Recover NTLM hashes from this output

To recover the NTLM hashes from the AD IFM data, the Powershell module [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) is required.

Once installed, use the SYSTEM hive in the IFM data to recover the hashes in the format `usernme:hash`:

```
$bootKey = Get-BootKey -SystemHivePath '.\registry\SYSTEM'
Get-ADDBAccount -All -DBPath '.\Active Directory\ntds.dit' -BootKey $bootKey | Format-Custom -View HashcatNT | Out-File ntlm_hashes.txt -Encoding ASCII
```
