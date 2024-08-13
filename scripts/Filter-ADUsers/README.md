# Filter Active Directory output
You can use the script Filter-ADUsers.ps1 to filter the following out from the IFM export from Active Directory:
- Disabled accounts
- Computer accounts

This saves you from processing accounts that aren’t useful.

**Note**: You will need to have Remote Server Administrative Tools (RSAT) added from optional features in Windows to use the `ActiveDirectory` PowerShell module.