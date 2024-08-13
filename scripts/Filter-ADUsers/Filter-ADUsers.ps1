<#
.DESCRIPTION
    This script Filters username and NTLM hash pairs from the given IFM output. It excludes entries that are for disabled users or computer accounts by checking against Active Directory using the ActiveDirectory module. Users are prompted to select a file at runtime.
.PARAMETER InputFile
    The input file selected by the user, containing username:hash pairs from the AD IFM dump.
.OUTPUTS
    A file named 'filtered_ad_hashes.txt' containing the filtered username:hash pairs from Active Directory output.
.EXAMPLE
    .\Filter-ADUsers.ps1
    This command runs the script and prompts the user to select an input file for processing.
#>

Import-Module ActiveDirectory
Add-Type -AssemblyName System.Windows.Forms

# Create an OpenFileDialog to prompt the user for a file
$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$OpenFileDialog.InitialDirectory = (Get-Location).Path
$OpenFileDialog.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*"
$OpenFileDialog.Title = "Select the hashes file"

# Show the dialog and get the selected file
$OpenFileDialog.ShowDialog() | Out-Null
$selectedFilePath = $OpenFileDialog.FileName

# Check if a file was selected
if (-not [string]::IsNullOrEmpty($selectedFilePath)) {
    # Initialize an array to store the output
    $outputArray = @()

    # Read the content of the selected file and process each line
    Get-Content $selectedFilePath | ForEach-Object {
        # Split each line into username and hash
        $username = $_.split(":")[0]
        $hash = $_.split(":")[1]

        # Check if the username does not end with a dollar sign - a computer account
        if ($username -notmatch '\$$') {
            if ($username -notmatch "[^a-zA-Z0-9.]") {
                $adUser = Get-ADUser -Filter "SamAccountName -eq '$username'"
                # Check if the user account is enabled
                if ($adUser.Enabled -eq $true) {
                    $outputArray += "$($username):$($hash)"
                }
            }
        }
    }

    $outputArray | Out-File -FilePath .\filtered_ad_hashes.txt

    Write-Output "Filtering complete. The output has been saved to 'filtered_ad_hashes.txt'."
} else {
    Write-Output "No file was selected. Exiting script."
}
