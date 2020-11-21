using namespace Microsoft.PowerShell.SecretManagement

function Unlock-1Password {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$AccountName
    )
    # the sign-in is unique for an AccountName and applies to any 1Password vaults in that account
    # at lease one SecretVault must be registered using SecretManagement.1Password to unlock the corresponding account
    # this is an interactive function, prompt for account password is done by 1Password_cli & not stored in PowerShell env
    # the --raw argument is given to op signin & the returned token is stored in an environment variable
    $opvaults = Get-SecretVault | Where-Object ModuleName -eq 'SecretManagement.1Password'
    $accounts = @($opvaults.VaultParameters.AccountName | Select-Object -Unique)
    if ($AccountName) {
        if ($AccountName -in $accounts) {
            # check to see if AccountName parameter is valid 1Password account
            Write-Verbose -Message "$AccountName is valid 1Password account."
        } else {
            throw "$AccountName is not a valid 1Password account."
        }
    } else {
        # no parameter was entered, use registered 1Password vaults to find account
        Write-Verbose -Message "finding 1Password account in registered vaults..."
        switch ($accounts.count) {
        0 { throw "Could not find 1Password account in registered vaults"} 
        1 { $AccountName = $accounts[0] }
        default {
            $AccountName = $accounts[0]
            Write-Warning -Message "Defaulted 1Password account to first $AccountName"
            }
        }
        Write-Verbose -Message "<$AccountName> from registered 1Password vaults being used."
    }
    # pull out other vault parameters related to authentication
    $VaultParameters = ($opvaults |
        Where-Object {$_.VaultParameters.AccountName -eq $AccountName} |
        Select-Object -First 1).VaultParameters

    $emailAddress = $VaultParameters.EmailAddress
    $secretKey = $VaultParameters.SecretKey
    Write-Verbose "SecretManagement.1Password: Testing authentication for Account:${AccountName}"

    $vaults = & op list vaults 2>$null | ConvertFrom-Json

    if ($null -eq $vaults) {
        # no vaults returned means we are not authenticated
        # prompt for master password interactively & put into env var
        # it does not matter whether env var already existed or not
        $token = & op signin $AccountName $emailAddress $secretKey --raw
        [System.Environment]::SetEnvironmentVariable("OP_SESSION_$AccountName", $token)
        Write-Verbose "Test listing vaults final"
        $vaults = & op list vaults --session $token 2>$null | ConvertFrom-Json
    }

    $vaults.count -ge 1
}