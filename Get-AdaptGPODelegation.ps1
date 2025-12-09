#requires -version 2

<#
    Get-AdaptGPODelegation.ps1 - Standalone Function
    Based on PowerView by Will Schroeder (@harmj0y)
    Original function: Get-AdaptGPODelegation
    
    Clean version - no PSReflect/Win32 signatures
#>

# --- Main Function: Get-AdaptGPODelegation ---
function Get-AdaptGPODelegation {
<#
.SYNOPSIS

Finds users with write permissions on GPO objects which may allow privilege escalation within the domain.

Author: Itamar Mizrahi (@MrAnde7son)  
License: BSD 3-Clause  
Required Dependencies: None  

.PARAMETER GPOName

The GPO display name to query for, wildcards accepted.

.PARAMETER PageSize

Specifies the PageSize to set for the LDAP searcher object.

.EXAMPLE

Get-AdaptGPODelegation

Returns all GPO delegations in current forest.

.EXAMPLE

Get-AdaptGPODelegation -GPOName

Returns all GPO delegations on a given GPO.
#>

    [CmdletBinding()]
    Param (
        [String]
        $GPOName = '*',

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    $Exclusions = @('SYSTEM','Domain Admins','Enterprise Admins')

    $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $DomainList = @($Forest.Domains)
    $Domains = $DomainList | foreach { $_.GetDirectoryEntry() }
    foreach ($Domain in $Domains) {
        $Filter = "(&(objectCategory=groupPolicyContainer)(displayname=$GPOName))"
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = $Domain
        $Searcher.Filter = $Filter
        $Searcher.PageSize = $PageSize
        $Searcher.SearchScope = "Subtree"
        $listGPO = $Searcher.FindAll()
        foreach ($gpo in $listGPO){
            $ACL = ([ADSI]$gpo.path).ObjectSecurity.Access | ? {$_.ActiveDirectoryRights -match "Write" -and $_.AccessControlType -eq "Allow" -and  $Exclusions -notcontains $_.IdentityReference.toString().split("\")[1] -and $_.IdentityReference -ne "CREATOR OWNER"}
        if ($ACL -ne $null){
            $GpoACL = New-Object psobject
            $GpoACL | Add-Member Noteproperty 'ADSPath' $gpo.Properties.adspath
            $GpoACL | Add-Member Noteproperty 'GPODisplayName' $gpo.Properties.displayname
            $GpoACL | Add-Member Noteproperty 'IdentityReference' $ACL.IdentityReference
            $GpoACL | Add-Member Noteproperty 'ActiveDirectoryRights' $ACL.ActiveDirectoryRights
            $GpoACL
        }
        }
    }
}
